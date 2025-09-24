contract MyEtherBank {

    uint256 private _donationPool = 0;

    // Allows the bank owner to withdraw accumulated donations
    function BankOwner_WithdrawDonations() public {
        if (_donationPool > 0) {
            uint256 withdrawalAmount = _donationPool;
            _donationPool = 0;
            if (!msg.sender.call.value(withdrawalAmount)()) { revert(); }
        }
    }
}