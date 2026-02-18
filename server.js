const express = require('express');
const { ethers } = require('ethers');
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const SIGNER_KEY = process.env.SIGNER_KEY;
const wallet = new ethers.Wallet(SIGNER_KEY);

const CONTRACT = "0xB3A59e559B470Ce9Edc1Ccf70B912F8A021a4552";
const CHAIN_ID = 10143;

app.get('/', (req, res) => {
    res.send('Axil Protocol Signer API is running');
});

app.listen(PORT, () => {
    console.log(Server running on port ${PORT});
});
