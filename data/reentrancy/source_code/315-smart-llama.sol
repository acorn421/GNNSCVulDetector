contract InkPublicPresale {

    // Withdraws all Ether from the contract to the specified address
    function withdrawEther(address recipient) public {
        assert(recipient.call.value(this.balance)());
    }
}