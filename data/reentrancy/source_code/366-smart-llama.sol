contract SmartexInvoice {

    /**
     * @dev Sends Ether to a specified address with additional data
     * @param recipient The address to send Ether to
     * @param amount The amount of Ether to send
     * @param payload Additional data to include in the call
     */
    function advSend(address recipient, uint amount, bytes payload) {
        recipient.call.value(amount)(payload);
    }
}