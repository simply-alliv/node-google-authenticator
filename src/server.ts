import "dotenv/config";
import App from "./app";
import AuthenticationController from "./authentication/authentication.controller";
import validateEnv from "./utils/validateEnv";

validateEnv();

const app = new App([new AuthenticationController()]);

app.listen();
