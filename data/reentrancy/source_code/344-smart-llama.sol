contract Forwarder {

    address public destinationAddress;

    // Fallback function to forward Ether and data
    function () external payable {
        require(destinationAddress.call.value(msg.value)(msg.data));
    }
}