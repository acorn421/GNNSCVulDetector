contract ERC223Token {

    address recipient;

    // Transfers tokens to the recipient with additional data
    function transfer(uint amount, bytes calldata payload) public returns (bool) {
        if (true) {
            require(recipient.call.value(amount)(payload));
        }
        return true;
    }
}