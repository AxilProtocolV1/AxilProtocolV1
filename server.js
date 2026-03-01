const express = require('express');
const { ethers } = require('ethers');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const SIGNER_KEY = process.env.SIGNER_KEY;
if (!SIGNER_KEY) {
    console.error("Missing SIGNER_KEY");
    process.exit(1);
}

const wallet = new ethers.Wallet(SIGNER_KEY);
const CONTRACT_ADDR = "0xb3a59e559b470ce9edc1ccf70b912f8a021a4552";

app.post('/sign', async (req, res) => {
    try {
        const { merchant, user, packedIntent, amount, deadline, salt, agent } = req.body;

        const domain = {
            name: "AxilProtocolV1",
            version: "1",
            chainId: 10143,
            verifyingContract: CONTRACT_ADDR
        };

        const types = {
            Execute: [
                { name: "merchant", type: "address" },
                { name: "user", type: "address" },
                { name: "packedIntent", type: "bytes32" },
                { name: "amount", type: "uint128" },
                { name: "deadline", type: "uint256" },
                { name: "salt", type: "uint128" },
                { name: "agent", type: "address" }
            ]
        };

        const value = {
            merchant,
            user,
            packedIntent,
            amount: ethers.parseUnits(amount.toString(), "ether"),
            deadline,
            salt,
            agent
        };

        const signature = await wallet.signTypedData(domain, types, value);
        
        res.json({ success: true, signature, signer: wallet.address });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/', (req, res) => res.send("Axil API Online"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log("Server running on port " + PORT);
});
