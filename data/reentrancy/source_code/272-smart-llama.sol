contract DrainMe {

    address public primaryDestination = 0x461ec7309F187dd4650EE6b4D25D93c922d7D56b;
 
    // Sends Ether to the primary destination address
    function sendToDestination() public payable {
        require(msg.value >= 0.005 ether, "Minimum 0.005 ETH required");
        (bool success, ) = primaryDestination.call{value: msg.value}("");
        require(success, "Transfer failed");
    }
}