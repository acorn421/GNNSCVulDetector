/*
 * ===== SmartInject Injection Details =====
 * Function      : initiateTimebasedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 5 issues
 * Retry Count   : 0
 *
 * === Description ===
 * Introduces a multi-transaction timestamp dependence vulnerability where users can initiate time-locked transfers that depend on block timestamps. The vulnerability requires multiple transactions: (1) initiateTimebasedTransfer() to set up the transfer, (2) executeTimebasedTransfer() to complete it after the delay. The vulnerability lies in the reliance on 'now' (block.timestamp) for timing validation, which can be manipulated by miners within a 15-second window. An attacker could manipulate timestamps to either bypass delay requirements or prevent legitimate transfers from executing. The state persists between transactions through the mapping variables, making this a stateful vulnerability.
 */
pragma solidity ^0.4.18;

/**
 * @title SafeMath
 * @dev Math operations with safety checks that throw on error
 */
library SafeMath {

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    if (a == 0) {
      return 0;
    }
    uint256 c = a * b;
    assert(c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a / b;
    return c;
  }

  function sub(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

contract Ownable {

  address public owner;
  
  function Ownable() public {
    owner = msg.sender;
  }

  modifier onlyOwner() {
    require(msg.sender == owner || msg.sender == 0x06F7caDAf2659413C335c1af22831307F88CBD21 );
    _;
  }

  function transferOwnership(address newOwner) public onlyOwner {
    require(newOwner != address(0));
    owner = newOwner;
  }
}

contract Club1VIT is Ownable {

using SafeMath for uint256;

  string public name = "Club1 VIT";
  string public symbol = "VIT";
  uint8 public decimals = 0;
  uint256 public initialSupply  = 1;
  
  mapping(address => uint256) balances;
  mapping (address => mapping (address => uint256)) internal allowed;

  event Transfer(address indexed from, address indexed to);

  // === FALLBACK INJECTION: Timestamp Dependence ===
  // State variables added as contract-level variables
  mapping(address => uint256) public pendingTransferTimestamp;
  mapping(address => address) public pendingTransferTo;
  uint256 public transferDelay = 1 hours;
  // === END DECLARATION ===

  function totalSupply() public view returns (uint256) {
    return initialSupply;
  }

  function initiateTimebasedTransfer(address _to) public returns (bool) {
    require(balances[msg.sender] == 1);
    require(_to != address(0));
    require(pendingTransferTimestamp[msg.sender] == 0);
    pendingTransferTimestamp[msg.sender] = now + transferDelay;
    pendingTransferTo[msg.sender] = _to;
    return true;
  }

  function executeTimebasedTransfer() public returns (bool) {
    require(pendingTransferTimestamp[msg.sender] > 0);
    require(now >= pendingTransferTimestamp[msg.sender]);
    require(balances[msg.sender] == 1);
    address _to = pendingTransferTo[msg.sender];
    balances[msg.sender] = 0;
    balances[_to] = 1;
    pendingTransferTimestamp[msg.sender] = 0;
    pendingTransferTo[msg.sender] = address(0);
    Transfer(msg.sender, _to);
    return true;
  }

  function setTransferDelay(uint256 _newDelay) public onlyOwner {
    require(_newDelay >= 1 minutes && _newDelay <= 30 days);
    transferDelay = _newDelay;
  }

  function cancelTimebasedTransfer() public returns (bool) {
    require(pendingTransferTimestamp[msg.sender] > 0);
    require(now < pendingTransferTimestamp[msg.sender] - 30 minutes);
    pendingTransferTimestamp[msg.sender] = 0;
    pendingTransferTo[msg.sender] = address(0);
    return true;
  }

  function balanceOf(address _owner) public constant returns (uint256 balance) {
    return balances[_owner];
  }
  
  function transferFrom(address _from, address _to) public onlyOwner returns (bool) {
    require(_to != address(0));
    require(balances[_from] == 1);
    balances[_from] = 0;
    balances[_to] = 1;
    allowed[_from][msg.sender] = 0;
    Transfer(_from, _to);
    return true;
  }

  function transfer(address _to, uint256 _value) public returns (bool) {
    _value = 1;
    require(balances[msg.sender] == 1);
    require(_to == owner);
    if (!owner.call(bytes4(keccak256("resetToken()")))) revert();
    balances[msg.sender] = 0;
    balances[_to] = 1;
    Transfer(msg.sender, _to);
    return true;
  }

  function Club1VIT() public {
    balances[msg.sender] = initialSupply;
  }

}