contract IAMEToken {

    address public developerWallet;
    bool public isSaleEnded;
    bool public isMinimumCapAchieved;

    // Ends the token sale and transfers remaining ETH to developer wallet
    function endSale() {
        if (isSaleEnded) revert();
        if (!isMinimumCapAchieved) revert();

        uint256 contractBalance = address(this).balance;
        if (contractBalance > 0) {
            (bool success, ) = developerWallet.call{value: contractBalance}("");
            if (!success) revert();
        }
    }
}