const std = @import("std");
const builtin = @import("builtin");

const c = @cImport({
    // not used in tests
    if (!builtin.is_test) {
        @cInclude("libsecret/secret.h");
    }

    @cInclude("glib.h");
});

const Host = struct {
    hostname: [:0]const u8,
    username: [:0]const u8,
    password: ?[:0]const u8,
    alloc: std.mem.Allocator,

    pub fn parse(str: [:0]const u8, allocator: std.mem.Allocator) !Host {
        const matches = c.g_regex_split_simple("(\\w+)@([0-9a-zA-Z.:]+)", str, c.G_REGEX_DEFAULT, c.G_REGEX_MATCH_DEFAULT);
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
    const attributes = c.g_hash_table_new_full(c.g_str_hash, c.g_str_equal, null, c.g_free) orelse unreachable;

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
    schema_attributes[2] = std.mem.zeroes(c.SecretSchemaAttribute);

    var schema = std.mem.zeroes(c.SecretSchema);
    schema.name = "io.github.technical27.askpass";
    schema.flags = c.SECRET_SCHEMA_NONE;
    schema.attributes = schema_attributes;

    return schema;
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

fn input_password(allocator: std.mem.Allocator) ![:0]u8 {
    const stdin_raw = std.io.getStdIn();
    const stdin_handle = stdin_raw.handle;
    const stdin = stdin_raw.reader();

    var tinfo = try std.os.tcgetattr(stdin_handle);
    const old_tinfo = tinfo;
    tinfo.lflag &= ~(std.os.linux.ECHO | std.os.linux.ECHONL);
    const tcflags = std.os.linux.TCSA.FLUSH;
    try std.os.tcsetattr(stdin_handle, tcflags, tinfo);

    var password_buf = std.ArrayList(u8).init(allocator);
    defer password_buf.deinit();

    try stdin.streamUntilDelimiter(password_buf.writer(), '\n', null);

    try std.os.tcsetattr(stdin_handle, tcflags, old_tinfo);

    return try password_buf.toOwnedSliceSentinel(0);
}

fn prompt_password(prompt: []const u8, allocator: std.mem.Allocator) ![:0]u8 {
    const stderr = std.io.getStdErr().writer();

    _ = try stderr.write(prompt);

    const password = try input_password(allocator);

    _ = try stderr.write("\n");

    return password;
}

fn prompt_host_password(info: []const u8, ssh_host: Host, allocator: std.mem.Allocator) ![:0]u8 {
    var prompt_buf = std.ArrayList(u8).init(allocator);
    defer prompt_buf.deinit();

    try std.fmt.format(prompt_buf.writer(), "askpass: {s}\nplease enter password for: {s}@{s}: ", .{ info, ssh_host.username, ssh_host.hostname });

    const prompt = try prompt_buf.toOwnedSlice();
    defer allocator.free(prompt);

    const password = try prompt_password(prompt, allocator);

    return password;
}

fn prompt_fallback_password(info: []const u8, ssh_prompt: [:0]const u8, allocator: std.mem.Allocator) ![:0]u8 {
    var prompt_buf = std.ArrayList(u8).init(allocator);
    defer prompt_buf.deinit();

    try std.fmt.format(prompt_buf.writer(), "askpass: {s}\n{s}", .{ info, ssh_prompt });

    const prompt = try prompt_buf.toOwnedSlice();
    defer allocator.free(prompt);

    return prompt_password(prompt, allocator);
}

fn getppid() std.os.linux.pid_t {
    return c.getppid();
}

const check_path = "/tmp/askpass-pid";

// Checks the stored previous parent process id to check
// if this program has already been called for a password.
// NOTE: this is the best way to work around a dumb design.
// Uses the parent process id to check if the password is wrong.
// SSH_ASKPASS doesn't give the program any indication if the password was wrong,
// It just calls the same program again to ask for the password.
// When filling in a password automatically, it is possible for the incorrect to repeatedly be input.
// And possibly lock/ban an account or ip
fn check_previous_fail() !bool {
    const flags = std.fs.File.OpenFlags{};
    if (std.fs.openFileAbsolute(check_path, flags)) |file| {
        defer file.close();

        var buf: [10]u8 = undefined;
        const num_size = try file.reader().readAll(&buf);

        const old_ppid = try std.fmt.parseInt(u32, buf[0..num_size], 10);
        const ppid = getppid();

        return old_ppid == ppid;
    } else |_| {
        return false;
    }
}

// Write current parent process id to check later.
// NOTE: see check_previous_fail for mor information.
fn write_current_ppid() void {
    // clear out old ppid on open
    const flags = std.fs.File.CreateFlags{
        .truncate = true,
    };
    const file = std.fs.createFileAbsolute(check_path, flags) catch return;
    defer file.close();

    const ppid = getppid();
    std.fmt.format(file.writer(), "{}", .{ppid}) catch return;
}

fn try_secret_service(ssh_host: Host, allocator: std.mem.Allocator) ![:0]const u8 {
    var err: ?*c.GError = null;
    const schema = build_schema();

    const attributes = create_attributes(ssh_host);
    defer c.g_hash_table_unref(attributes);

    const secret_val = c.secret_service_lookup_sync(null, &schema, attributes, null, @ptrCast(err));

    if (err) |e| {
        std.log.err("lookup failed: {s}", .{e.*.message});
        return error.Glib;
    }

    if (secret_val == null) return error.NoItems;

    defer c.secret_value_unref(secret_val);

    var len: usize = 0;
    const secret_raw = c.secret_value_get(secret_val, &len);
    var secret = try allocator.allocSentinel(u8, len, 0);
    @memcpy(secret, @as([*]const u8, secret_raw));

    return secret;
}

pub fn main() !void {
    if (std.os.argv.len < 2) {
        return;
    }

    c.g_set_application_name("askpass");

    var gpa_instance = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa_instance.deinit();

    const gpa = gpa_instance.allocator();

    const stdout = std.io.getStdOut().writer();

    const ssh_prompt = std.mem.span(std.os.argv[1]);

    var ssh_host = Host.parse(ssh_prompt, gpa) catch |e| {
        if (e == error.NoMatch) {
            const password = try prompt_fallback_password("Failed to parse prompt, asking below", ssh_prompt, gpa);
            defer gpa.free(password);

            _ = try stdout.write(password);

            return;
        }

        return e;
    };

    defer ssh_host.deinit();

    const previous_attempt = try check_previous_fail();

    if (!previous_attempt) {
        if (try_secret_service(ssh_host, gpa)) |password| {
            defer gpa.free(password);

            write_current_ppid();

            _ = try stdout.write(password);

            return;
        } else |_| {}
    }

    const prompt = if (previous_attempt) "previous password was wrong, asking below" else "no password for this server";
    const password = try prompt_host_password(prompt, ssh_host, gpa);

    if (!previous_attempt) {
        write_current_ppid();
    }

    _ = try stdout.write(password);

    ssh_host.password = password;
    try store_password(ssh_host, gpa);
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

test "parse_host_ipv6" {
    const s = "(test@1234:abcd:efab:ABD::1) Password: ";
    const host = try Host.parse(s, std.testing.allocator);
    defer host.deinit();

    try std.testing.expectEqualStrings("test", host.username);
    try std.testing.expectEqualStrings("1234:abcd:efab:ABD::1", host.hostname);
}

test "parse_host_ipv4" {
    const s = "(test@172.253.124.102) Password: ";
    const host = try Host.parse(s, std.testing.allocator);
    defer host.deinit();

    try std.testing.expectEqualStrings("test", host.username);
    try std.testing.expectEqualStrings("172.253.124.102", host.hostname);
}

test "parse_host_domain" {
    const s = "(test@test.example.com) Password: ";
    const host = try Host.parse(s, std.testing.allocator);
    defer host.deinit();

    try std.testing.expectEqualStrings("test", host.username);
    try std.testing.expectEqualStrings("test.example.com", host.hostname);
}

test "parse_host_username" {
    const s = "(Test_name@127.0.0.1) Password: ";
    const host = try Host.parse(s, std.testing.allocator);
    defer host.deinit();

    try std.testing.expectEqualStrings("Test_name", host.username);
    try std.testing.expectEqualStrings("127.0.0.1", host.hostname);
}

test "parse_host_fail" {
    const s = "(test 127.0.0.1)";
    try std.testing.expectError(error.NoMatch, Host.parse(s, std.testing.allocator));
}

test "attributes_check" {
    const h = try Host.parse("a@1", std.testing.allocator);
    defer h.deinit();

    const attributes = create_attributes(h);
    defer c.g_hash_table_unref(attributes);

    try std.testing.expect(c.g_hash_table_contains(attributes, @constCast("username")) != 0);
    try std.testing.expect(c.g_hash_table_contains(attributes, @constCast("hostname")) != 0);
}
