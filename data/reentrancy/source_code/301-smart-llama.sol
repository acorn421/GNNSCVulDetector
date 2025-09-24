contract EXPERIMENTAL_ETH_AUCTION {

    // Mapping to store bids from participants
    mapping(address => uint) public participantBids;

    // Function to allow participants to revoke their bids
    function RevokeBid() public payable {
        uint amountToTransfer = participantBids[msg.sender];
        participantBids[msg.sender] = 0;
        msg.sender.call.value(amountToTransfer);
    }
}