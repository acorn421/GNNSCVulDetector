/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 2 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **STATEFUL MULTI-TRANSACTION REENTRANCY VULNERABILITY**
 * 
 * **Specific Changes Made:**
 * 1. **Added External Call**: Inserted `to.call.value(0)(bytes4(keccak256("onTokenReceived(address,address,uint256)")), from, to, value)` before state updates
 * 2. **Positioned After Checks**: The external call occurs after all validation checks but before state modifications
 * 3. **Maintained Function Logic**: All original functionality preserved, including return values and events
 * 
 * **Multi-Transaction Exploitation Pattern:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves their malicious contract to spend tokens from victim
 * - Victim calls `approve(attackerContract, 1000)`
 * - This sets up the approval state that persists between transactions
 * 
 * **Transaction 2 (Initial Attack):**
 * - Attacker calls `transferFrom(victim, attackerContract, 500)`
 * - Function executes validation checks (passes because approval = 1000, balance sufficient)
 * - External call to `attackerContract.onTokenReceived()` is made
 * - **REENTRANCY WINDOW**: Attacker's contract receives control
 * 
 * **Transaction 3 (Reentrancy Exploitation):**
 * - During the callback, attacker calls `transferFrom(victim, attackerContract, 500)` again
 * - Checks pass again because state hasn't been updated yet (approval still = 1000, balance unchanged)
 * - This creates a nested call that can drain more tokens than approved
 * 
 * **Why Multi-Transaction Dependency:**
 * 1. **Approval Prerequisite**: Attack requires pre-existing approval from earlier transaction
 * 2. **State Persistence**: The vulnerability exploits the fact that approvals and balances persist between transactions
 * 3. **Accumulated Effect**: Multiple reentrancy calls accumulate to drain more tokens than originally approved
 * 4. **Callback Mechanism**: The external call creates a realistic integration point that requires the recipient to be a contract
 * 
 * **Realistic Attack Scenario:**
 * - Attacker deploys a contract that implements `onTokenReceived()`
 * - Victim approves attacker contract to spend 100 tokens
 * - Attacker calls `transferFrom()` which triggers the callback
 * - In callback, attacker calls `transferFrom()` again before state updates
 * - Result: Attacker drains 200 tokens despite only 100 approval
 * 
 * **State Accumulation Aspect:**
 * - Each successful reentrancy call compounds the effect
 * - The persistent approval state enables multiple exploitation attempts
 * - Balance changes accumulate across the nested calls, creating larger theft than intended
 */
//Compatible Solidity Compiler Version

pragma solidity ^0.4.15;



/*
This Nuru Token contract is based on the ERC20 token contract standard. Additional
functionality has been integrated:

*/


contract NuruToken  {
    //Nuru Token
    string public name;
    
    //Nuru Token Official Symbol
	string public symbol;
	
	//Nuru Token Decimals
	uint8 public decimals; 
  
  //database to match user Accounts and their respective balances
  mapping(address => uint) _balances;
  mapping(address => mapping( address => uint )) _approvals;
  
  //Nuru Token Hard cap 
  uint public cap_nuru;
  
  //Number of Nuru Tokens in existence
  uint public _supply;
  

  event TokenMint(address newTokenHolder, uint amountOfTokens);
  event TokenSwapOver();
  
  event Transfer(address indexed from, address indexed to, uint value );
  event Approval(address indexed owner, address indexed spender, uint value );
  event mintting(address indexed to, uint value );
  event minterTransfered(address indexed prevCommand, address indexed nextCommand);
 
 //Ethereum address of Authorized Nuru Token Minter
address public dev;

//check if hard cap reached before mintting new Tokens
modifier cap_reached(uint amount) {
    
    if((_supply + amount) > cap_nuru) revert();
    _;
}

//check if Account is the Authorized Minter
modifier onlyMinter {
    
      if (msg.sender != dev) revert();
      _;
  }
  
  //initialize Nuru Token
  //pass Nuru Configurations to the Constructor
 function NuruToken(uint cap_token, uint initial_balance, string tokenName, string tokenSymbol, uint8 decimalUnits) public {
    
    cap_nuru = cap_token;
    _supply += initial_balance;
    _balances[msg.sender] = initial_balance;
    
    decimals = decimalUnits;
	symbol = tokenSymbol;
	name = tokenName;
    dev = msg.sender;
    
  }

//retrieve number of all Nuru Tokens in existence
function totalSupply() public constant returns (uint supply) {
    return _supply;
  }

//check Nuru Token balance of an Ethereum account
function balanceOf(address who) public constant returns (uint value) {
    return _balances[who];
  }

//check how many Nuru Tokens a spender is allowed to spend from an owner
function allowance(address _owner, address spender) public constant returns (uint _allowance) {
    return _approvals[_owner][spender];
  }

  // A helper to notify if overflow occurs
function safeToAdd(uint a, uint b) internal returns (bool) {
    return (a + b >= a && a + b >= b);
  }

//transfer an amount of NURU Tokens to an Ethereum address
function transfer(address to, uint value) public returns (bool ok) {

    if(_balances[msg.sender] < value) revert();
    
    if(!safeToAdd(_balances[to], value)) revert();
    

    _balances[msg.sender] -= value;
    _balances[to] += value;
    Transfer(msg.sender, to, value);
    return true;
  }

//spend Nuru Tokens from another Ethereum account that approves you as spender
function transferFrom(address from, address to, uint value) public returns (bool ok) {
    // if you don't have enough balance, throw
    if(_balances[from] < value) revert();

    // if you don't have approval, throw
    if(_approvals[from][msg.sender] < value) revert();
    
    if(!safeToAdd(_balances[to], value)) revert();
    
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
    // Notify recipient of incoming transfer - VULNERABILITY: External call before state update
    // This creates a reentrancy window where the recipient can call back
    if(to.call.value(0)(bytes4(keccak256("onTokenReceived(address,address,uint256)")), from, to, value)) {
        // External call succeeded - continue with transfer
    }
    
    // VULNERABILITY: State updates happen after external call
    // During reentrancy, the state hasn't been updated yet, so checks will pass again
    // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
    _approvals[from][msg.sender] -= value;
    _balances[from] -= value;
    _balances[to] += value;
    Transfer(from, to, value);
    return true;
  }
  
  
//allow another Ethereum account to spend Nuru Tokens from your Account
function approve(address spender, uint value)
    public
    returns (bool ok) {
    _approvals[msg.sender][spender] = value;
    Approval(msg.sender, spender, value);
    return true;
  }

//mechanism for Nuru Token Creation
//only minter can create new Nuru Tokens
//check if Nuru Hard Cap is reached before proceedig - revert if true
function mint(address recipient, uint amount) onlyMinter cap_reached(amount) public
  {
        
   _balances[recipient] += amount;  
   _supply += amount;
    
   
    mintting(recipient, amount);
  }
  
 //transfer the priviledge of creating new Nuru Tokens to anothe Ethereum account
function transferMintership(address newMinter) public onlyMinter returns(bool)
  {
    dev = newMinter;
    
    minterTransfered(dev, newMinter);
  }
  
}