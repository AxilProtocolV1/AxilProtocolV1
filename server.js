const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const SIGNER_KEY = process.env.SIGNER_KEY;
const ALCHEMY_RPC_URL = process.env.ALCHEMY_RPC_URL;

if (!SIGNER_KEY || !ALCHEMY_RPC_URL) {
    console.error("ERROR: Missing SIGNER_KEY or ALCHEMY_RPC_URL");
    process.exit(1);
}

const provider = new ethers.JsonRpcProvider(ALCHEMY_RPC_URL);
const wallet = new ethers.Wallet(SIGNER_KEY, provider);

app.post('/sign', async (req, res) => {
    try {
        const { merchant, user, agent, amount, salt, intentText } = req.body;
        const domain = { name: "AxilProtocol", version: "1", chainId: 1, verifyingContract: merchant };
        const types = {
            Intent: [
                { name: "user", type: "address" },
                { name: "agent", type: "address" },
                { name: "amount", type: "uint256" },
                { name: "salt", type: "uint256" },
                { name: "intentText", type: "string" }
            ]
        };
        const value = { user, agent, amount: ethers.parseEther(amount.toString()), salt, intentText: intentText || "" };
        const signature = await wallet.signTypedData(domain, types, value);
        console.log("Success: Signed for " + user);
        res.json({ success: true, signature, signer: wallet.address });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/', (req, res) => res.send("Axil Protocol Signer API is Online"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
