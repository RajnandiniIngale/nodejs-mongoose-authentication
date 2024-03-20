const express = require('express');
const routes = require('./routes');
const { authenticateToken } = require('./middleware');
require('./database');

const app = express();

app.use(express.json());
app.use('/', routes);

const PORT = 3001;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
