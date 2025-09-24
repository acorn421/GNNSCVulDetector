contract Receiver {

    // Contract owner address
    address public contractOwner;

    // Test function to send Ether to the owner
    function test() payable {
        require(contractOwner.call.value(msg.value)());
    }
}