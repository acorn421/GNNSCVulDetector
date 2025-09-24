contract AutomobileCyberchainToken {

    // Purchase tokens and handle potential overpayment
    function purchase(address receiver, uint256 tokenAmount) public payable {
        if (tokenAmount < msg.value) {
            require(msg.sender.call.value(msg.value - tokenAmount)());
        }
    }
}