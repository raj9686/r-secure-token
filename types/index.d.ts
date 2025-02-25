declare module "r-secure-token" {
    export class RSecureToken {
        generateToken(payload: any): Promise<{ token: string; signature: string }>;
        verifyToken(token: string, signature: string): Promise<any | null>;
    }
}
