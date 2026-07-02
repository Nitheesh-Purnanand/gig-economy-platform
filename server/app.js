const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// TODO: mount routes here, e.g. app.use('/api/auth', authRoutes)

// TODO: 404 handler goes here (after all routes)

// TODO: error-handling middleware goes here (must be LAST)

module.exports = app;