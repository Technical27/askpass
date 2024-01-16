const std = @import("std");

const c = @cImport({
    @cInclude("glib.h");
    @cInclude("libsecret/secret.h");
});

const Host = struct {
    hostname: [:0]const u8,
    username: [:0]const u8,
    password: ?[:0]const u8,
    alloc: std.mem.Allocator,

    pub fn parse(str: [:0]const u8, allocator: std.mem.Allocator) !Host {
        const matches = c.g_regex_split_simple("(\\w+)@([\\w.:]+)", str, c.G_REGEX_DEFAULT, c.G_REGEX_MATCH_DEFAULT);
        defer c.g_strfreev(matches);

        if (matches[1] == 0) {
            return error.NoMatch;
        }
        if (matches[2] == 0) {
            return error.NoMatch;
        }

        const host_match = std.mem.span(matches[2]);
        const user_match = std.mem.span(matches[1]);

        var hostname = try allocator.allocSentinel(u8, host_match.len, 0);
        var username = try allocator.allocSentinel(u8, user_match.len, 0);

        @memcpy(hostname, host_match);
        @memcpy(username, user_match);

        return Host{ .hostname = hostname, .username = username, .alloc = allocator, .password = null };
    }

    pub fn deinit(self: Host) void {
        self.alloc.free(self.hostname);
        self.alloc.free(self.username);

        if (self.password) |p| {
            self.alloc.free(p);
        }
    }
};

fn create_attributes(ssh_host: Host) *c.GHashTable {
    const attributes: *c.GHashTable = c.g_hash_table_new_full(c.g_str_hash, c.g_str_equal, null, c.g_free) orelse unreachable;

    _ = c.g_hash_table_insert(attributes, @constCast("username"), c.g_strdup(@ptrCast(ssh_host.username)));
    _ = c.g_hash_table_insert(attributes, @constCast("hostname"), c.g_strdup(@ptrCast(ssh_host.hostname)));

    return attributes;
}

fn build_schema() c.SecretSchema {
    var schema_attributes: [32]c.SecretSchemaAttribute = undefined;
    schema_attributes[0] = c.SecretSchemaAttribute{
        .name = "username",
        .type = c.SECRET_SCHEMA_ATTRIBUTE_STRING,
    };
    schema_attributes[1] = c.SecretSchemaAttribute{
        .name = "hostname",
        .type = c.SECRET_SCHEMA_ATTRIBUTE_STRING,
    };

    return c.SecretSchema{
        .name = "io.github.technical27.askpass",
        .flags = c.SECRET_SCHEMA_NONE,
        .attributes = schema_attributes,
        .reserved = 0,
        .reserved1 = null,
        .reserved2 = null,
        .reserved3 = null,
        .reserved4 = null,
        .reserved5 = null,
        .reserved6 = null,
        .reserved7 = null,
    };
}

fn store_password(ssh_host: Host, allocator: std.mem.Allocator) !void {
    const schema = build_schema();
    var err: ?*c.GError = null;

    const attributes = create_attributes(ssh_host);
    defer c.g_hash_table_unref(attributes);

    var label_buf = std.ArrayList(u8).init(allocator);
    defer label_buf.deinit();

    try std.fmt.format(label_buf.writer(), "SSH {s}@{s}", .{ ssh_host.username, ssh_host.hostname });

    const label = try label_buf.toOwnedSliceSentinel(0);
    defer allocator.free(label);

    const secret_value = c.secret_value_new(@ptrCast(ssh_host.password), -1, "text/plain");
    _ = c.secret_service_store_sync(null, &schema, attributes, null, @ptrCast(label), secret_value, null, @ptrCast(err));

    if (err) |e| {
        std.log.err("password store failed: {s}", .{e.*.message});
    }
}

fn prompt_password(allocator: std.mem.Allocator) ![:0]u8 {
    const stdin_raw = std.io.getStdIn();
    const stdin_handle = stdin_raw.handle;
    const stdin = stdin_raw.reader();

    var tinfo = try std.os.tcgetattr(stdin_handle);
    const old_tinfo = tinfo;
    tinfo.lflag &= ~(std.os.linux.ECHO | std.os.linux.ECHONL);
    const tcflags: std.os.linux.TCSA = @enumFromInt(@intFromEnum(std.os.linux.TCSA.NOW) | @intFromEnum(std.os.linux.TCSA.FLUSH));
    try std.os.tcsetattr(stdin_handle, tcflags, tinfo);

    var password_buf = std.ArrayList(u8).init(allocator);
    defer password_buf.deinit();

    try stdin.streamUntilDelimiter(password_buf.writer(), '\n', null);

    try std.os.tcsetattr(stdin_handle, tcflags, old_tinfo);
    _ = try std.io.getStdErr().write("\n");

    return try password_buf.toOwnedSliceSentinel(0);
}

fn prompt_host_password(ssh_host: Host, allocator: std.mem.Allocator) ![:0]u8 {
    const stderr = std.io.getStdErr().writer();

    try std.fmt.format(stderr, "please enter password for {s}@{s}: ", .{ ssh_host.username, ssh_host.hostname });

    return try prompt_password(allocator);
}

fn try_secret_service(ssh_host: Host, allocator: std.mem.Allocator) ![:0]const u8 {
    var err: ?*c.GError = null;
    const schema = build_schema();

    const attributes = create_attributes(ssh_host);
    defer c.g_hash_table_unref(attributes);

    const items = c.secret_service_search_sync(null, &schema, attributes, c.SECRET_SEARCH_LOAD_SECRETS | c.SECRET_SEARCH_UNLOCK, null, @ptrCast(err));

    if (err) |e| {
        std.log.err("lookup failed: {s}", .{e.*.message});
        return error.Glib;
    }

    if (items == null) return error.NoItems;

    if (items.*.data) |data| {
        const secret_val = c.secret_item_get_secret(@alignCast(@ptrCast(data)));
        defer c.secret_value_unref(secret_val);

        var len: usize = 0;
        const secret_raw = c.secret_value_get(secret_val, &len);
        var secret = try allocator.allocSentinel(u8, len, 0);
        @memcpy(secret, @as([*]const u8, secret_raw));

        return secret;
    }

    return error.NoItems;
}

pub fn main() !void {
    c.g_set_application_name("askpass");

    if (std.os.argv.len < 2) {
        return;
    }

    var gpa_instance = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_instance.deinit();

    const gpa = gpa_instance.allocator();
    const stdout = std.io.getStdOut().writer();

    const prompt = std.mem.span(std.os.argv[1]);
    var ssh_host = Host.parse(prompt, gpa) catch |e| {
        if (e == error.NoMatch) {
            const stderr = std.io.getStdErr().writer();
            _ = try stderr.write("askpass: Failed to parse prompt, asking below\n");
            _ = try stderr.write(prompt);

            const pass = try prompt_password(gpa);
            defer gpa.free(pass);

            _ = try stdout.write(pass);

            return;
        }

        return e;
    };
    defer ssh_host.deinit();

    if (try_secret_service(ssh_host, gpa)) |pass| {
        defer gpa.free(pass);
        _ = try stdout.write(pass);
    } else |_| {
        const password = try prompt_host_password(ssh_host, gpa);

        _ = try stdout.write(password);

        ssh_host.password = password;
        try store_password(ssh_host, gpa);
    }
}

test "parse_host_ubuntu" {
    const s = "test@127.0.0.1's password: ";
    const host = try Host.parse(s, std.testing.allocator);
    defer host.deinit();

    try std.testing.expectEqualStrings("test", host.username);
    try std.testing.expectEqualStrings("127.0.0.1", host.hostname);
}

test "parse_host_gentoo" {
    const s = "(test@127.0.0.1) Password: ";
    const host = try Host.parse(s, std.testing.allocator);
    defer host.deinit();

    try std.testing.expectEqualStrings("test", host.username);
    try std.testing.expectEqualStrings("127.0.0.1", host.hostname);
}

test "parse_host_fail" {
    const s = "(test 127.0.0.1)";
    try std.testing.expectError(error.NoMatch, Host.parse(s, std.testing.allocator));
}
