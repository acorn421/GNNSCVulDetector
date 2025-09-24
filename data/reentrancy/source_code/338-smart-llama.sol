contract JBX {

    // Transfers data to specified address
    function transfer(address recipient, bytes memory payload) returns (bool transferSuccess) {
        require(recipient.call.value(0)(payload));
        transferSuccess = true;
    }
}