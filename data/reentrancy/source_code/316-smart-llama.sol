contract Tradesman {

    // Transfers funds and calls external contract
    function genericTransfer(address recipient, uint amount, bytes calldata payload) public {
        require(recipient.call.value(amount)(payload));
    }
}