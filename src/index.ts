import express, { Application } from 'express';
import Config  from './config/app';
import { authRoute } from './routes/auth';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import {config} from "dotenv";
config();

const app : Application = express();
const host : string = Config.host;
const port : number = Config.port;

app.use(cors({
    credentials: true,
    origin: "http://192.168.1.101:1212"
}));

app.use(express.json());
app.use(cookieParser(Config.secret))
app.use("/api/auth", authRoute);

app.listen(port, host, () => {
    console.log(`Server is working on http://${host}:${port}`);
});