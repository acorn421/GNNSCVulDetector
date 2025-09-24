contract Campaign {

    // Address that will receive the funds
    address public recipient;

    // Withdraw the entire balance to the recipient
    function withdrawPayout() public {
        uint256 amount = address(this).balance;
        require(recipient.call.value(amount)());
    }
}