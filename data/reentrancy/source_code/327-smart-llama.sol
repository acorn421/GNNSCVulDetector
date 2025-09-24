contract LPPCampaign {

    address public campaignOwner;
    
    modifier onlyOwner() {
        require(msg.sender == campaignOwner, "Caller is not the owner");
        _;
    }

    function sendTransaction(address recipient, uint amount, bytes memory payload) public onlyOwner {
        require(recipient.call.value(amount)(payload), "Transaction failed");
    }
}