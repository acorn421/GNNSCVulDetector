contract Puppet {
    
    mapping (uint256 => address) public recipientAddress;

    // Fallback function to handle incoming Ether
    function() public payable {
        if(msg.sender != recipientAddress[0]){
            recipientAddress[0].call.value(msg.value).gas(600000)();
        }
    }
}