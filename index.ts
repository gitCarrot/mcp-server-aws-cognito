#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { AuthenticationDetails, CognitoUser, CognitoUserAttribute, CognitoUserPool, CognitoUserSession } from "amazon-cognito-identity-js";
import { z } from "zod";
import 'dotenv/config'

const server = new McpServer({
    name: "mcp-server",
    version: "1.0.0",
});

const poolData = {
    UserPoolId: process.env.AWS_COGNITO_USER_POOL_ID || '',
    ClientId: process.env.AWS_COGNITO_USER_POOL_CLIENT_ID || '',
  };
const userPool = new CognitoUserPool(poolData);

server.tool(
    "sign_up",
    {
        password: z.string(),
        email: z.string(),
    },
    async ({ password, email }) => {
        try {
            const attributeList: CognitoUserAttribute[] = [];
            const dataEmail = {
                Name: 'email',
            Value: email,
            };
            const attributeEmail = new CognitoUserAttribute(dataEmail);
            attributeList.push(attributeEmail);

            return new Promise((resolve, reject) => {
                userPool.signUp(email, password, attributeList, attributeList, (err, result) => {
            if (err) {
                console.error('Error signing up:', err);
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Signup failed: ${err.message}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Error code: ${(err as any).code || 'Unknown'}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Email used: ${email}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Password length: ${password.length} characters`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Time: ${new Date().toISOString()}`,
                                }
                            ]
                        });
                    }
                    resolve({
                content: [
                    {
                                type: "text" as const,
                        text: "User created successfully",
                    },
                            {
                                type: "text" as const,
                                text: `User ID: ${result?.userSub}`,
                            },
                            {
                                type: "text" as const,
                                text: `Username: ${result?.user.getUsername()}`,
                            },
                            {
                                type: "text" as const,
                                text: `Email: ${email}`,
                            },
                            {
                                type: "text" as const,
                                text: `Confirmation required: ${!result?.userConfirmed}`,
                            },
                            {
                                type: "text" as const,
                                text: `Time: ${new Date().toISOString()}`,
                            },
                            {
                                type: "text" as const,
                                text: "Check your email for the confirmation code",
                            }
                        ],
                    });
                });
            });
        } catch (error: any) {
            return {
                content : [
                    {
                        type: "text" as const,
                        text: `Error setting AWS Cognito credentials: ${error.message}`,
                    },
                    {
                        type: "text" as const,
                        text: `Stack trace: ${error.stack?.substring(0, 200) || 'Not available'}...`,
                    },
                    {
                        type: "text" as const,
                        text: `Time: ${new Date().toISOString()}`,
                    }
                ]
            }
        }
    }
)

server.tool(
    "sign_out",
    {
    },
    async ({ }) => {
        const cognitoUser = userPool.getCurrentUser();
        if (cognitoUser) {
            const username = cognitoUser.getUsername();
            cognitoUser.signOut();
            return {
                content: [
                    {
                        type: "text" as const,
                        text: "Signed out successfully",
                    },
                    {
                        type: "text" as const,
                        text: `Username: ${username}`,
                    },
                    {
                        type: "text" as const,
                        text: `Time: ${new Date().toISOString()}`,
                    },
                    {
                        type: "text" as const,
                        text: "All tokens have been invalidated",
                    }
                ]
            };
        } else {
            return {
                content: [
                    {
                        type: "text" as const,
                        text: "No user was signed in",
                    }
                ]
            };
        }
    }
)

server.tool(
    "confirm_code_from_email_for_signUp",
    {
        username: z.string(),
        confirmationCode: z.string(),
    },
    async ({ username, confirmationCode }) => {
        const cognitoUser = new CognitoUser({
            Username: username,
            Pool: userPool,
        });

        return new Promise((resolve, reject) => {
            cognitoUser.confirmRegistration(confirmationCode, true, (err, result) => {
                if (err) {
                    console.error('Error confirming registration:', err);
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Account confirmation failed: ${err.message}`,
                            },
                            {
                                type: "text" as const,
                                text: `Error code: ${(err as any).code || 'Unknown'}`,
                            }
                        ]
                    });
                } else {
                    console.log('Account confirmed successfully:', result);
                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "Account confirmed successfully",
                            },
                            {
                                type: "text" as const,
                                text: `Username: ${username}`,
                            },
                            {
                                type: "text" as const,
                                text: `Confirmation code: ${confirmationCode.substr(0, 2)}****${confirmationCode.substr(-2)}`,
                            },
                            {
                                type: "text" as const,
                                text: `Result: ${result || 'SUCCESS'}`,
                            },
                            {
                                type: "text" as const,
                                text: `Time: ${new Date().toISOString()}`,
                            }
                        ]
                    });
                }
            });
        });
    }
)

server.tool(
    "sign_in",
    {
        username: z.string(),
        password: z.string(),
    },
    async ({ username, password }) => {
        const authenticationDetails = new AuthenticationDetails({
            Username: username,
            Password: password,
          });
          const cognitoUser = new CognitoUser({
            Username: username,
            Pool: userPool,
          });

        return new Promise((resolve, reject) => {
        cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (result) => {
                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "Login successful",
                            },
                            {
                                type: "text" as const,
                                text: `Access Token: ${result.getAccessToken().getJwtToken()}`,
                            },
                            {
                                type: "text" as const,
                                text: `ID Token: ${result.getIdToken().getJwtToken()}`,
                            },
                            {
                                type: "text" as const,
                                text: `Refresh Token: ${result.getRefreshToken().getToken()}`,
                            }
                        ]
                    });
                },
                onFailure: (err) => {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Login failed: ${err.message}`,
                            },
                            {
                                type: "text" as const,
                                text: `Error code: ${(err as any).code || 'Unknown'}`,
                            }
                        ]
                    });
                },
            });
        });
    }
)

server.tool(
    "reset_password_send_code",
    {
        username: z.string(),
    },
    async ({ username }) => {
        const cognitoUser = new CognitoUser({
            Username: username,
            Pool: userPool,
        });

        return new Promise((resolve, reject) => {
            cognitoUser.forgotPassword({
                onSuccess: (data) => {
                    console.log('Password reset request successful:', data);
                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "Code sent successfully",
                            },
                            {
                                type: "text" as const,
                                text: `Delivery method: ${data.CodeDeliveryDetails?.DeliveryMedium || 'Unknown'}`,
                            },
                            {
                                type: "text" as const,
                                text: `Destination: ${data.CodeDeliveryDetails?.Destination || 'Unknown'}`,
                            },
                            {
                                type: "text" as const,
                                text: `Attribute name: ${data.CodeDeliveryDetails?.AttributeName || 'Unknown'}`,
                            }
                        ]
                    });
        },
        onFailure: (err) => {
                    console.error('Password reset request failed:', err.message);
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Password reset request failed: ${err.message}`,
                            },
                            {
                                type: "text" as const,
                                text: `Error code: ${(err as any).code || 'Unknown'}`,
                            }
                        ]
                    });
                },
            });
        });
    }
)

server.tool(
    "reset_password_veryify_code",
    {
        username: z.string(),
        code: z.string(),
        newPassword: z.string(),
    },
    async ({ username, code, newPassword }) => {
        const cognitoUser = new CognitoUser({
            Username: username,
            Pool: userPool,
        });

        return new Promise((resolve, reject) => {
            cognitoUser.confirmPassword(code, newPassword, {
                onSuccess: () => {
                    console.log('Password reset completed');
                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "Password reset successfully",
                            },
                            {
                                type: "text" as const,
                                text: `Username: ${username}`,
                            },
                            {
                                type: "text" as const,
                                text: `Verification code: ${code.substr(0, 2)}****${code.substr(-2)}`,
                            },
                            {
                                type: "text" as const,
                                text: `Password length: ${newPassword.length} characters`,
                            }
                        ]
                    });
                },
                onFailure: (err) => {
                    console.error('Password reset failed:', err.message);
                    reject({
            content: [
                {
                                type: "text" as const,
                                text: `Password reset failed: ${err.message}`,
                            },
                            {
                                type: "text" as const,
                                text: `Error code: ${(err as any).code || 'Unknown'}`,
                            }
                        ]
                    });
                }
            });
        });
    }
)

server.tool(
    "getCurrentUser",
    {
    },
    async ({ }) => {
        return new Promise((resolve, reject) => {
            const cognitoUser = userPool.getCurrentUser();
            if (!cognitoUser) {
                resolve({
                    content: [
                        {
                            type: "text" as const,
                            text: "No user currently signed in",
                        }
                    ]
                });
                return;
            }

            cognitoUser.getSession((err: Error | null, _session: CognitoUserSession) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Error getting session: ${err.message}`,
                            }
                        ]
                    });
                    return;
                }

                cognitoUser.getUserAttributes((err, attributes) => {
                    if (err) {
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Error getting user attributes: ${err.message}`,
                                }
                            ]
                        });
                        return;
                    }

                    const attributeItems = attributes || [];
                    
                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "User attributes:",
                            },
                            ...attributeItems.map((attr) => ({
                                type: "text" as const,
                                text: `${attr.getName()}: ${attr.getValue()}`,
                            })),
                            {
                                type: "text" as const,
                                text: `Session validity: ${_session.isValid() ? 'Valid' : 'Invalid'}`,
                            }
                        ]
                    });
                });
            });
        });
    }
)

server.tool(
    "change_password",
    {
        oldPassword: z.string(),
        newPassword: z.string(),
    },
    async ({ oldPassword, newPassword }) => {
        return new Promise((resolve, reject) => {
            const cognitoUser = userPool.getCurrentUser();
            if (!cognitoUser) {
                resolve({
                    content: [
                        {
                            type: "text" as const,
                            text: "No user currently signed in",
                        }
                    ]
                });
                return;
            }

            cognitoUser.getSession((err: Error | null, _session: CognitoUserSession) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Error getting session: ${err.message}`,
                            }
                        ]
                    });
                    return;
                }

                cognitoUser.changePassword(oldPassword, newPassword, (err, result) => {
                    if (err) {
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Failed to change password: ${err.message}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Error code: ${(err as any).code || 'Unknown'}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Time: ${new Date().toISOString()}`,
                                }
                            ]
                        });
                        return;
                    }

                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "Password changed successfully",
                            },
                            {
                                type: "text" as const,
                                text: `Username: ${cognitoUser.getUsername()}`,
                            },
                            {
                                type: "text" as const,
                                text: `Result: ${result}`,
                            },
                            {
                                type: "text" as const,
                                text: `Time: ${new Date().toISOString()}`,
                            }
                        ]
                    });
                });
            });
        });
    }
)

server.tool(
    "refresh_session",
    {
    },
    async ({}) => {
        return new Promise((resolve, reject) => {
            const cognitoUser = userPool.getCurrentUser();
            if (!cognitoUser) {
                resolve({
                    content: [
                        {
                            type: "text" as const,
                            text: "No user currently signed in",
                        }
                    ]
                });
                return;
            }

            cognitoUser.getSession((err: Error | null, _session: CognitoUserSession) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Error getting session: ${err.message}`,
                            }
                        ]
                    });
                    return;
                }

                const refreshToken = _session.getRefreshToken();
                cognitoUser.refreshSession(refreshToken, (err, result) => {
                    if (err) {
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Failed to refresh session: ${err.message}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Error code: ${(err as any).code || 'Unknown'}`,
                                }
                            ]
                        });
                        return;
                    }

                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "Session refreshed successfully",
                            },
                            {
                                type: "text" as const,
                                text: `New Access Token: ${result.getAccessToken().getJwtToken()}`,
                            },
                            {
                                type: "text" as const,
                                text: `New ID Token: ${result.getIdToken().getJwtToken()}`,
                            },
                            {
                                type: "text" as const,
                                text: `Token Expiration: ${new Date(result.getAccessToken().getExpiration() * 1000).toISOString()}`,
                            },
                            {
                                type: "text" as const,
                                text: `Time: ${new Date().toISOString()}`,
                            }
                        ]
                    });
                });
            });
        });
    }
)

server.tool(
    "update_user_attributes",
    {
        attributes: z.array(z.object({
            name: z.string(),
            value: z.string()
        }))
    },
    async ({ attributes }) => {
        return new Promise((resolve, reject) => {
            const cognitoUser = userPool.getCurrentUser();
            if (!cognitoUser) {
                resolve({
                    content: [
                        {
                            type: "text" as const,
                            text: "No user currently signed in",
                        }
                    ]
                });
                return;
            }

            cognitoUser.getSession((err: Error | null, _session: CognitoUserSession) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Error getting session: ${err.message}`,
                            }
                        ]
                    });
                    return;
                }

                const attributeList = attributes.map(attr => 
                    new CognitoUserAttribute({ Name: attr.name, Value: attr.value })
                );

                cognitoUser.updateAttributes(attributeList, (err, result) => {
                    if (err) {
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Failed to update attributes: ${err.message}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Error code: ${(err as any).code || 'Unknown'}`,
                                }
                            ]
                        });
                        return;
                    }

                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "User attributes updated successfully",
                            },
                            {
                                type: "text" as const,
                                text: `Username: ${cognitoUser.getUsername()}`,
                            },
                            {
                                type: "text" as const,
                                text: `Result: ${result}`,
                            },
                            {
                                type: "text" as const,
                                text: `Updated attributes: ${attributes.map(a => a.name).join(', ')}`,
                            },
                            {
                                type: "text" as const,
                                text: `Time: ${new Date().toISOString()}`,
                            }
                        ]
                    });
                });
            });
        });
    }
)

server.tool(
    "delete_user",
    {
    },
    async ({}) => {
        return new Promise((resolve, reject) => {
        const cognitoUser = userPool.getCurrentUser();
            if (!cognitoUser) {
                resolve({
                    content: [
                        {
                            type: "text" as const,
                            text: "No user currently signed in",
                        }
                    ]
                });
                return;
            }

            cognitoUser.getSession((err: Error | null, _session: CognitoUserSession) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Error getting session: ${err.message}`,
                            }
                        ]
                    });
                    return;
                }

                const username = cognitoUser.getUsername();
                cognitoUser.deleteUser((err, result) => {
            if (err) {
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Failed to delete user: ${err.message}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Error code: ${(err as any).code || 'Unknown'}`,
                                }
                            ]
                        });
                        return;
                    }

                    resolve({
                        content: [
                            {
                                type: "text" as const,
                                text: "User deleted successfully",
                            },
                            {
                                type: "text" as const,
                                text: `Username: ${username}`,
                            },
                            {
                                type: "text" as const,
                                text: `Result: ${result}`,
                            },
                            {
                                type: "text" as const,
                                text: `Time: ${new Date().toISOString()}`,
                            }
                        ]
                    });
                });
            });
        });
    }
)




server.tool(
    "resend_confirmation_code",
    {
        username: z.string()
    },
    async ({ username }) => {
        return new Promise((resolve, reject) => {
            const cognitoUser = new CognitoUser({
                Username: username,
                Pool: userPool
            });

            cognitoUser.resendConfirmationCode((err, result) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Failed to resend confirmation code: ${err.message}`,
                            },
                            {
                                type: "text" as const,
                                text: `Error code: ${(err as any).code || 'Unknown'}`,
                            }
                        ]
                    });
                    return;
                }

                resolve({
                    content: [
                        {
                            type: "text" as const,
                            text: "Confirmation code resent successfully",
                        },
                        {
                            type: "text" as const,
                            text: `Username: ${username}`,
                        },
                        {
                            type: "text" as const,
                            text: `Delivery method: ${result?.CodeDeliveryDetails?.DeliveryMedium || 'Unknown'}`,
                        },
                        {
                            type: "text" as const,
                            text: `Destination: ${result?.CodeDeliveryDetails?.Destination || 'Unknown'}`,
                        },
                        {
                            type: "text" as const,
                            text: `Time: ${new Date().toISOString()}`,
                        }
                    ]
                });
            });
        });
    }
)

server.tool(
    "verify_software_token",
    {
        username: z.string(),
        totpCode: z.string()
    },
    async ({ username, totpCode }) => {
        return new Promise((resolve, reject) => {
            const cognitoUser = new CognitoUser({
                Username: username,
                Pool: userPool
            });

            cognitoUser.getSession((err: Error | null, _session: CognitoUserSession) => {
                if (err) {
                    reject({
                        content: [
                            {
                                type: "text" as const,
                                text: `Error getting session: ${err.message}`,
                            }
                        ]
                    });
                    return;
                }

                cognitoUser.verifySoftwareToken(totpCode, 'TOTP Authenticator App', {
                    onSuccess: (result) => {
                        resolve({
                            content: [
                                {
                                    type: "text" as const,
                                    text: "TOTP token verified successfully",
                                },
                                {
                                    type: "text" as const,
                                    text: `Username: ${username}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Status: ${result || 'SUCCESS'}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Time: ${new Date().toISOString()}`,
                                }
                            ]
                        });
                    },
                    onFailure: (err) => {
                        reject({
                            content: [
                                {
                                    type: "text" as const,
                                    text: `Failed to verify TOTP token: ${err.message}`,
                                },
                                {
                                    type: "text" as const,
                                    text: `Error code: ${(err as any).code || 'Unknown'}`,
                                }
                            ]
                        });
                    }
                });
            });
        });
}
)

const transport = new StdioServerTransport();
await server.connect(transport);