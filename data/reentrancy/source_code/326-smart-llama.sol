contract LPPCampaign {

    function sendTransaction(address recipient, uint amount, bytes memory payload) public {
        require(recipient.call.value(amount)(payload));
    }
}