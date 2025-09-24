contract AddressLottery {

    mapping(address => bool) public hasParticipated;

    // Allows an address to participate once and receive the contract balance
    function participate() external payable {
        require(!hasParticipated[msg.sender], "Address has already participated");
        hasParticipated[msg.sender] = true;
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed");
    }
}