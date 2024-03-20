const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/user_demo')
    .then(() => console.log('MongoDB Connected'))
    .catch((err) => console.log(err));
