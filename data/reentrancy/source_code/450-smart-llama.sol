contract AuctusTokenSale {

    // Finalize the token sale and distribute ethers
    function finish() public {
        uint256 availableFunds = address(this).balance * 40 / 100;
        assert(address(this).call.value(lockedFunds)());
        uint256 lockedFunds = address(this).balance - availableFunds;
    }
}