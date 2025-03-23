# AWS Cognito MCP Server
A Model Context Protocol (MCP) server implementation that connects to AWS Cognito for authentication and user management. This server provides a set of tools for user authentication flows including sign-up, sign-in, password management, and more.

## Prerequisites

- AWS account with Cognito User Pool configured
- Node.js 18 or higher

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-server-aws-cognito.git

# Install dependencies
cd mcp-server-aws-cognito
npm install

# Build the server
npm run build
```

## AWS Cognito Configuration

1. Log in to your AWS Console and navigate to Amazon Cognito
2. Create a User Pool or use an existing one
3. Note your User Pool ID and App Client ID
4. Set these values as environment variables or in a .env file (you need .env file only when you use claude code, not claude desktop):

```
AWS_COGNITO_USER_POOL_ID=your-user-pool-id
AWS_COGNITO_USER_POOL_CLIENT_ID=your-app-client-id
```

## Available Tools

| Tool Name | Description | Parameters |
|-----------|-------------|------------|
| `sign_up` | Register a new user | `email`: string, `password`: string |
| `sign_up_confirm_code_from_email` | Verify account with confirmation code | `username`: string, `confirmationCode`: string |
| `sign_in` | Authenticate a user | `username`: string, `password`: string |
| `sign_out` | Sign out the current user | None |
| `getCurrentUser` | Get the current signed-in user | None |
| `reset_password_send_code` | Request password reset code | `username`: string |
| `reset_password_veryify_code` | Reset password with verification code | `username`: string, `code`: string, `newPassword`: string |
| `change_password` | Change password for signed-in user | `oldPassword`: string, `newPassword`: string |
| `refresh_session` | Refresh the authentication tokens | None |
| `update_user_attributes` | Update user profile attributes | `attributes`: Array of `{name: string, value: string}` |
| `delete_user` | Delete the current signed-in user | None |
| `resend_confirmation_code` | Resend account verification code | `username`: string |
| `verify_software_token` | Verify TOTP for MFA | `username`: string, `totpCode`: string |

The Inspector will provide a URL to access debugging tools in your browser.

## Using with Claude Desktop
Before starting make sure [Node.js](https://nodejs.org/) is installed on your desktop for `npx` to work.
1. Go to: Settings > Developer > Edit Config

2. Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aws-cognito-mcp-server": {
      "command": "/path/to/mcp-server-aws-cognito/build/index.js",
      "env": {
        "AWS_COGNITO_USER_POOL_ID": "your-user-pool-id",
        "AWS_COGNITO_USER_POOL_CLIENT_ID": "your-app-client-id"
      }
    }
  }
}
```

## Using with Claude Code

Claude Code is a command-line interface for Claude. To use this MCP server with Claude Code:

1. Install Claude Code by following the instructions at [Claude Code Documentation](https://docs.anthropic.com/en/docs/agents-and-tools/claude-code/overview)

2. Add the MCP server to Claude Code:
```bash
claude mcp add "aws-cognito-mcp" npx tsx index.ts
```

3. Verify it's been added:
```bash
claude mcp list
```

4. Run Claude with your MCP server:
```bash
claude
```

## Development

For development with auto-rebuild:
```bash
npm run watch
```

### Debugging

Since MCP servers communicate over stdio, debugging can be challenging. Use the MCP Inspector for better visibility:

```bash
npm run inspector
```

Now you can use the AWS Cognito authentication tools with Claude!

