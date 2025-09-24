interface FoMo3DlongInterface {
  function getBuyPrice() external view returns(uint256);
  function getTimeLeft() external view returns(uint256);
}

contract PwnFoMo3D {

    FoMo3DlongInterface private fomo3dInstance;

    // Execute the main logic if time left is less than or equal to 50
    function executePurchase() external {
        if (fomo3dInstance.getTimeLeft() > 50) { revert(); }
        uint256 purchaseAmount = fomo3dInstance.getBuyPrice() * 2;
        (bool success, ) = address(fomo3dInstance).call{value: purchaseAmount}("");
        require(success, "Purchase failed");
    }
}