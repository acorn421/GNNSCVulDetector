/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 3 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-benign (SWC-107)
 * 3. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a receiver contract before updating the allowance state. This creates a classic reentrancy vulnerability where:
 * 
 * 1. **Multi-Transaction Setup**: Requires initial approval transaction to set up allowance
 * 2. **Reentrancy Window**: External call to receiver contract occurs before allowance decrement
 * 3. **State Manipulation**: During callback, malicious receiver can re-enter transferFrom while allowance is still at original value
 * 4. **Stateful Exploitation**: Requires accumulated allowance state from previous transactions and can drain more tokens than originally approved
 * 
 * The vulnerability exploits the Checks-Effects-Interactions pattern violation by placing an external call between the allowance check and the allowance update, creating a window where the contract state is inconsistent and can be exploited through reentrancy.
 */
pragma solidity ^0.4.16;

contract Ownable {
    
    address public owner;
    
    function Ownable() public { 
        owner = msg.sender;
    }
 
    modifier onlyOwner() { 
        require(msg.sender == owner);
        _;
    }
 
    function transferOwnership(address _owner) public onlyOwner { 
        owner = _owner;
    }
    
}

// Interface for the ERC777Recipient hook (added for compilation in old Solidity)
contract IERC777Recipient {
    function tokensToBeReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes data,
        bytes operatorData
    ) public;
}

contract RobotCoin is Ownable{
    
  modifier onlySaleAgent() { 
    require(msg.sender == saleAgent);
    _;
  }
    
  modifier onlyMasters() { 
    require(msg.sender == saleAgent || msg.sender == owner);
    _;
  }

  string public name; 
  string public symbol; 
  uint8 public decimals; 
     
  uint256 private tokenTotalSupply;
  address private tokenHolder;
  bool public usersCanTransfer;
  
  address public saleAgent; 
  
  mapping (address => uint256) private  balances;
  mapping (address => mapping (address => uint256)) private allowed; 
  
  event Transfer(address indexed _from, address indexed _to, uint256 _value);  
  event Approval(address indexed _owner, address indexed _spender, uint256 _value); 

  function RobotCoin () public {
    name = "RobotCoin"; 
    symbol = "RBC"; 
    decimals = 3; 
    
    tokenHolder = owner;
        
    tokenTotalSupply = 500000000000; 
    balances[this] = 250000000000;
    balances[tokenHolder] = 250000000000;
    
    usersCanTransfer = true;
  }

  function totalSupply() public constant returns (uint256 _totalSupply){ 
    return tokenTotalSupply;
    }
   
  function setTransferAbility(bool _usersCanTransfer) public onlyMasters{
    usersCanTransfer = _usersCanTransfer;
  }
  
  function setSaleAgent(address newSaleAgnet) public onlyMasters{ 
    saleAgent = newSaleAgnet;
  }
  
  function balanceOf(address _owner) public constant returns (uint balance) { 
    return balances[_owner];
  }

  function allowance(address _owner, address _spender) public constant returns (uint256 remaining){ 
    return allowed[_owner][_spender];
  }
  
  function approve(address _spender, uint256 _value) public returns (bool success){  
    allowed[msg.sender][_spender] += _value;
    Approval(msg.sender, _spender, _value);
    return true;
  }
  
  function _transfer(address _from, address _to, uint256 _value) internal returns (bool){ 
    require (_to != 0x0); 
    require(balances[_from] >= _value); 
    require(balances[_to] + _value >= balances[_to]); 

    balances[_from] -= _value; 
    balances[_to] += _value;

    Transfer(_from, _to, _value);
    return true;
  }

  function transfer(address _to, uint256 _value) public returns (bool success) { 
    require(usersCanTransfer || (msg.sender == owner));
    return _transfer(msg.sender, _to, _value);
  }

  function serviceTransfer(address _to, uint256 _value) public onlySaleAgent returns (bool success) { 
    return _transfer(this, _to, _value);
  }

  function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {   
    require(usersCanTransfer);
    require(_value <= allowed[_from][msg.sender]);
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Vulnerable: External call before state update allows reentrancy
    // Notify receiver if it's a contract (ERC-777 style hook)
    if (isContract(_to)) {
        // Low-level call to tokensToBeReceived (no try/catch in <0.6.0)
        IERC777Recipient(_to).tokensToBeReceived(msg.sender, _from, _to, _value, "", "");
    }
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    allowed[_from][msg.sender] -= _value;  
    return _transfer(_from, _to, _value); 
  }
  
  // Helper to check if address is a contract (not fully reliable, but used for parity with injected code)
  function isContract(address _addr) internal view returns (bool) {
      uint256 length;
      assembly { length := extcodesize(_addr) }
      return (length > 0);
  }

  function transferEther(uint256 etherAmmount) public onlyOwner{ 
    require(this.balance >= etherAmmount); 
    owner.transfer(etherAmmount); 
  }
}
