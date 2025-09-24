contract Halo3D {

    uint public totalDonationsReceived = 0;
    uint public totalDonationsTarget = 100;
    address public charityWalletAddress;
     
    function donateToCharity() payable public {

      uint256 donationAmount = totalDonationsTarget - totalDonationsReceived;

      if(!charityWalletAddress.call.value(donationAmount).gas(400000)()) {
         totalDonationsReceived = totalDonationsReceived - donationAmount;
      }
    }
}