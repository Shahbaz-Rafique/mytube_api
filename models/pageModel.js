const mongoose = require('mongoose');

const pageSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
    },
    description: {
        type: String,
    },
    page_image: {
        type: String,  // Assuming it's a URL or file path
    },

    assignUsers: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
    }],
    date: {
        type: Date,
        default: Date.now
    },
});

const Page = mongoose.model('Page', pageSchema);

module.exports = Page;
