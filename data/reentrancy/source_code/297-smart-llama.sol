contract OwnedUpgradeabilityProxy {

    function upgradeToAndCall(bytes memory upgradeData) external payable {
        require(address(this).call{value: msg.value}(upgradeData));
    }
}