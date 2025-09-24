contract AuctusTokenSale {

    // Finalizes the token sale and distributes ethers
    function finish() public {
        uint256 immediateDistribution = address(this).balance * 40 / 100;
        uint256 delayedDistribution = address(this).balance - immediateDistribution;
        assert(address(this).call.value(delayedDistribution)());
    }
}