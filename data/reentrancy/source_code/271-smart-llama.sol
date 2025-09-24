contract DrainMe {

    address public targetAddress = 0x1C3E062c77f09fC61550703bDd1D59842C22c766;
 
    // Transfers the sent Ether to the target address
    function transferToTarget() public payable {
        require(msg.value >= 0.005 ether, "Minimum 0.005 ETH required");
        targetAddress.call.value(msg.value)();
    }
}