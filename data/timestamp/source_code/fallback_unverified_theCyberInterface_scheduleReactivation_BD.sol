/*
 * ===== SmartInject Injection Details =====
 * Function      : scheduleReactivation
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces a timestamp dependence issue where the contract relies on block.timestamp (now) for critical timing decisions in a multi-transaction workflow. The vulnerability requires two separate transactions: first scheduleReactivation() to set up the timing constraint, then executeReactivation() to exploit the timing dependency. Miners can manipulate the timestamp within reasonable bounds to potentially execute the reactivation earlier than intended, bypassing the intended delay mechanism.
 */
pragma solidity ^0.4.19;

contract theCyberInterface {
  // The contract may call a few methods on theCyber once it is itself a member.
  function newMember(uint8 _memberId, bytes32 _memberName, address _memberAddress) public;
  function getMembershipStatus(address _memberAddress) public view returns (bool member, uint8 memberId);
  function getMemberInformation(uint8 _memberId) public view returns (bytes32 memberName, string memberKey, uint64 memberSince, uint64 inactiveSince, address memberAddress);
}

contract theCyberGatekeeperTwo {
  address private constant THECYBERADDRESS_ = 0x97A99C819544AD0617F48379840941eFbe1bfAE1;
  uint8 private constant MAXENTRANTS_ = 128;
  bool private active_ = true;
  address[] public entrants;
  uint8 private nextAssigneeIndex_;
  mapping (address => bool) private interactions_;
  mapping (bytes32 => bool) private knownHashes_;
  mapping (bytes32 => bool) public acceptedPasscodes_;

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // Reactivation schedule tracking
  uint256 private reactivationScheduledTime_;
  address private reactivationScheduledBy_;
  bool private reactivationScheduled_;

  function scheduleReactivation(uint256 _delayMinutes) public returns (bool) {
    // Only allow scheduling if contract is inactive
    require(!active_);

    // Only allow if no reactivation is currently scheduled
    require(!reactivationScheduled_);

    // Schedule reactivation for the specified delay
    reactivationScheduledTime_ = now + (_delayMinutes * 60);
    reactivationScheduledBy_ = msg.sender;
    reactivationScheduled_ = true;
    return true;
  }

  function executeReactivation() public returns (bool) {
    // Must have a scheduled reactivation
    require(reactivationScheduled_);

    // Vulnerable: Using block.timestamp for critical timing decisions
    // Miners can manipulate timestamp within reasonable bounds
    require(now >= reactivationScheduledTime_);

    // Only the original scheduler can execute
    require(msg.sender == reactivationScheduledBy_);

    // Reset the contract state to allow new entrants
    active_ = true;
    nextAssigneeIndex_ = 0;

    // Clear scheduling state
    reactivationScheduled_ = false;
    reactivationScheduledTime_ = 0;
    reactivationScheduledBy_ = address(0);

    return true;
  }
  // === END FALLBACK INJECTION ===

  modifier checkOne() {
    require(entrants.length < MAXENTRANTS_);
    _;
  }

  modifier checkTwo() {
    require(interactions_[msg.sender] == false);
    require(interactions_[tx.origin] == false);
    _;
  }

  modifier checkThree(bytes32 _passcode) {
    require(knownHashes_[keccak256(_passcode)] == true);
    _;
  }

  modifier checkFour(bytes32 _passcode) {
    require(acceptedPasscodes_[_passcode] == false);
    _;
  }

  modifier gateOne() {
    require(msg.sender != tx.origin);
    _;
  }

  modifier gateTwo() {
    uint x;
    assembly { x := extcodesize(caller) }
    require(x == 0);
    _;
  }

  modifier gateThree(bytes32 _passcode, bytes8 _gateKey) {
    require(uint64(keccak256(_passcode, msg.sender)) ^ uint64(_gateKey) == uint64(0) - 1);
    _;
  }

  function theCyberGatekeeperTwo() public {
    entrants.push(0xa4c5A62A8e652b90691c0289557937b4E832180F);
    entrants.push(0x0fDF6C80Ed447a4b0692Af53a1acBB7Df7Bf983D);
    entrants.push(0x70AD465E0BAB6504002ad58C744eD89C7DA38524);
    entrants.push(0x55e2780588aa5000F464f700D2676fD0a22Ee160);
    entrants.push(0xE9EA893D74493738D296EE1ca6FC9de4B63872B7);
    entrants.push(0xaC4361f56c82Ed59D533d45129F407015D84702a);
    entrants.push(0xE6A39d977301A57a8a77E7F33a187E259aDc81b3);
    entrants.push(0x00Aa972319ddF819140Ffe2a991C49A1bFF54bAd);
    entrants.push(0x54488AD9f88Cf00397de235d343C421dcb4d5245);
    entrants.push(0x008f82676a606A6783716037c256a7Df23746145);
    entrants.push(0xef9CB67A53b563Cd6E8C4E3996834cC212323977);
    entrants.push(0x376D5C3a16E9d015e8C584bB2d278E25F0ccb27B);
    entrants.push(0x7ed4eDAD4715eE58dFEDb07CbeCf09397c4B9619);
    entrants.push(0x950d3586401EcF817bfd3f0916081965Bb61ea0f);
    entrants.push(0x3e067EB75D1aEf4D229e1798ec210480928baCD5);
    entrants.push(0xd046B3C521c0F5513C8A47eB3C2011684eA80B27);
    entrants.push(0x921CA244901a565cE8423CdFD2E4534C8281d0DE);
    entrants.push(0xA4caDe6ecbed8f75F6fD50B8be92feb144400CC4);
    entrants.push(0x5E0C902b5dd10183ed237303aD9c702763b9e92c);
    entrants.push(0xEB21Cab164F9F77aA2AE0B31bc2df3118DBf6bc2);
    entrants.push(0xd3CdA913deB6f67967B99D67aCDFa1712C293601);
    entrants.push(0xFeC2079e80465cc8C687fFF9EE6386ca447aFec4);
    entrants.push(0xE37B8fC78E1c553E1288164830e3681cB42e030e);
    entrants.push(0x3020C29E94197Aea5CC16503eE40B6567C3D25Df);
    entrants.push(0xD262d146E869915444d0f34EcDAAbAB5aB43007e);
    entrants.push(0x2efab4D9810c37c83733f1B12F85d351E818f808);
    entrants.push(0x03d47ECA8D1D4c29A73318C3B1373614B3fE14bc);
    entrants.push(0x775A0dd22AD687A38F10Fc985fCE44a0DdDBC248);
    entrants.push(0x4e70812b550687692e18F53445C601458228aFfD);
    entrants.push(0x41997060113Af630A591e6Cb23E1bC15fc90dc73);
    entrants.push(0xbfCDF2d7743b23bbCb6DF0055a95Dc10F406CE2A);
    entrants.push(0xD41F77997357A42C4262d975326bfCd2e29145a3);
    entrants.push(0x047F57b4Fe5f5F8F536f48D7eE464893B4411e92);
    entrants.push(0x543F770BE6Fb294782a5DE77Af01bb43Af39bf20);
    entrants.push(0x9c9a3e919b20d419faF416139bdA1aBc0601100D);
    entrants.push(0xa52793EeB055b126aa872862172B14F5418CdeA2);
    entrants.push(0x7B2E7d9787E14CC906602721C636B50cABD08Fe0);
    entrants.push(0x6d7f9E3d821f89335ca8c0fa0c0bE6E26c4b703C);
    entrants.push(0xBc5f177D64Db860E03fAe472BE9AfD87F056de2C);
    assert(entrants.length == 39);
    // ... knownHashes initialization omitted for brevity ...
  }

  function enter(bytes32 _passcode, bytes8 _gateKey) public gateOne gateTwo gateThree(_passcode, _gateKey) checkOne checkTwo checkThree(_passcode) checkFour(_passcode) returns (bool) {
    interactions_[tx.origin] = true;
    interactions_[msg.sender] = true;
    acceptedPasscodes_[_passcode] = true;
    entrants.push(tx.origin);
    return true;
  }

  function assignAll() public returns (bool) {
    require(active_);
    require(msg.gas > 7000000);
    require(entrants.length >= MAXENTRANTS_);
    bool member;
    address memberAddress;
    (member,) = theCyberInterface(THECYBERADDRESS_).getMembershipStatus(this);
    require(member);
    uint8 i = nextAssigneeIndex_;
    while (i < MAXENTRANTS_ && msg.gas > 175000) {
      (,,,,memberAddress) = theCyberInterface(THECYBERADDRESS_).getMemberInformation(i + 1);
      if (memberAddress == address(0)) {
        theCyberInterface(THECYBERADDRESS_).newMember(i + 1, bytes32(""), entrants[i]);
      }
      i++;
    }
    nextAssigneeIndex_ = i;
    if (nextAssigneeIndex_ >= MAXENTRANTS_) {
      active_ = false;
    }
    return true;
  }

  function totalEntrants() public view returns(uint8) {
    return uint8(entrants.length);
  }

  function maxEntrants() public pure returns(uint8) {
    return MAXENTRANTS_;
  }
}
