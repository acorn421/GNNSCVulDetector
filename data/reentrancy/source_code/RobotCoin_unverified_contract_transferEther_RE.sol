/*
 * ===== SmartInject Injection Details =====
 * Function      : transferEther
 * Vulnerability : Reentrancy
 * Status        : Not Detected
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This modification introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding Persistent State Variables**: 
 *    - `pendingWithdrawals` mapping tracks withdrawal amounts between transactions
 *    - `lastWithdrawalTime` mapping enforces cooldown periods
 *    - `WITHDRAWAL_COOLDOWN` constant creates time-based state dependency
 * 
 * 2. **Creating Multi-Transaction Flow**:
 *    - First transaction: Sets up pending withdrawal and records timestamp
 *    - Second transaction: Processes the pending withdrawal with external call
 *    - State persists between these separate transactions
 * 
 * 3. **Reentrancy Vulnerability**:
 *    - External call `owner.transfer(etherAmmount)` occurs before state cleanup
 *    - `pendingWithdrawals[msg.sender] = 0` happens after the external call
 *    - If owner is a malicious contract, it can call back into `transferEther` during the transfer
 *    - The callback finds `pendingWithdrawals[msg.sender]` still set to the original amount
 *    - This allows multiple withdrawals of the same amount in a single transaction chain
 * 
 * 4. **Multi-Transaction Exploitation**:
 *    - **Transaction 1**: Owner calls `transferEther(100)` → Sets `pendingWithdrawals[owner] = 100`
 *    - **Transaction 2**: Owner calls `transferEther(100)` → Processes withdrawal, calls `owner.transfer(100)`
 *    - **During Transfer**: Malicious owner contract receives callback and immediately calls `transferEther(100)` again
 *    - **Reentrancy**: Since `pendingWithdrawals[owner]` is still 100 (not cleared yet), the check passes
 *    - **Result**: Multiple transfers of 100 ether occur before state is cleaned up
 * 
 * 5. **State Dependency**: The vulnerability requires the accumulated state from Transaction 1 to be exploitable in Transaction 2, making it inherently multi-transaction and stateful.
 * 
 * This creates a realistic vulnerability where the pending withdrawal system, intended for security, actually creates a reentrancy attack vector that spans multiple transactions.
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
    require(_value <= allowed[_from][_to]);
    allowed[_from][_to] -= _value;  
    return _transfer(_from, _to, _value); 
  }
  
  // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
mapping(address => uint256) private pendingWithdrawals;
  mapping(address => uint256) private lastWithdrawalTime;
  uint256 private constant WITHDRAWAL_COOLDOWN = 1 hours;
  
  function transferEther(uint256 etherAmmount) public onlyOwner{ 
    require(this.balance >= etherAmmount); 
    
    // Check if this is an initial withdrawal request or processing a pending one
    if (pendingWithdrawals[msg.sender] == 0) {
      // First transaction: Set up pending withdrawal
      require(block.timestamp >= lastWithdrawalTime[msg.sender] + WITHDRAWAL_COOLDOWN);
      pendingWithdrawals[msg.sender] = etherAmmount;
      lastWithdrawalTime[msg.sender] = block.timestamp;
      return;
    }
    
    // Second+ transaction: Process pending withdrawal
    require(pendingWithdrawals[msg.sender] == etherAmmount);
    
    // VULNERABILITY: External call before state cleanup
    owner.transfer(etherAmmount);
    
    // State cleanup happens after external call (vulnerable to reentrancy)
    pendingWithdrawals[msg.sender] = 0;
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
}