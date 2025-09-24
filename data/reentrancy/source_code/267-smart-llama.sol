contract TokensGate {

    /**
     * @dev Transfers ETH to a specified wallet address
     * @param recipient The address to receive the ETH
     * @param amountInWei The amount of ETH to transfer in wei
     */
    function transferEth(address recipient, uint256 amountInWei) payable public {
        require(address(this).balance >= amountInWei, "Insufficient contract balance");
        require(address(this) != recipient, "Cannot transfer to self");
        require(recipient.call.value(amountInWei)(), "Transfer failed");
    }
}