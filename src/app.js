import express from 'express';
import cors from 'cors';
const app = express();

// Basic configuration
app.use(express.json({limit: "16kb"}));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static('public'));


// cors configuration 
app.use(cors({
    origin: process.env.CORS_ORIGIN?.split(",") || 'http://localhost:5173',
    credentials:true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH',"OPTIONS"],
    allowedHeaders: ['Content-Type', 'Authorization']

}));

// import the routes

import healthCheckRouter from './routes/healthcheck.route.js';

app.use('/api/v1/healthcheck', healthCheckRouter);

app.get('/', (req, res) => {
    res.send('Hello, World!');
});
export default app;