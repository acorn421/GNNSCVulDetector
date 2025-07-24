/*
 * ===== SmartInject Injection Details =====
 * Function      : mint
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 2 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-events (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability by adding an external call to a recipient callback function after state updates but before the final event emission. This creates a realistic token notification mechanism that allows malicious recipients to re-enter the mint function during the external call, enabling exploitation across multiple transactions through accumulated state manipulation.
 * 
 * **Specific Changes Made:**
 * 1. Added recipient contract size check using `recipient.code.length > 0`
 * 2. Inserted external call using `recipient.call()` to invoke `onTokenMinted(uint256)` callback
 * 3. Positioned the external call after state updates but before final event emission
 * 4. Used low-level `call()` to make the vulnerability more subtle and realistic
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 1. **Transaction 1**: Attacker deploys malicious recipient contract with `onTokenMinted()` callback
 * 2. **Transaction 2**: Minter calls `mint()` with attacker's contract as recipient
 * 3. **Reentrancy Trigger**: When external call reaches malicious contract, it re-enters `mint()`
 * 4. **State Accumulation**: Multiple reentrancy cycles accumulate state inconsistencies
 * 5. **Transaction 3+**: Attacker exploits accumulated state to drain tokens or bypass supply cap
 * 
 * **Why Multi-Transaction Exploitation is Required:**
 * - The vulnerability requires pre-deployment of malicious recipient contract (Transaction 1)
 * - Each mint call can trigger multiple reentrancy cycles, accumulating state changes
 * - The supply cap and balance checks can be bypassed through accumulated reentrancy
 * - Exploitation requires building up state across multiple mint operations
 * - The attacker needs separate transactions to setup, exploit, and extract value
 * 
 * **Realistic Integration Rationale:**
 * - Token recipient notifications are common in modern DeFi protocols
 * - The callback mechanism allows recipients to react to minted tokens
 * - External calls for compliance/KYC verification are realistic additions
 * - The vulnerability appears as a legitimate feature enhancement
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
  constructor(uint cap_token, uint initial_balance, string tokenName, string tokenSymbol, uint8 decimalUnits) public {
    
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
    emit Transfer(msg.sender, to, value);
    return true;
  }

//spend Nuru Tokens from another Ethereum account that approves you as spender
function transferFrom(address from, address to, uint value) public returns (bool ok) {
    // if you don't have enough balance, throw
    if(_balances[from] < value) revert();

    // if you don't have approval, throw
    if(_approvals[from][msg.sender] < value) revert();
    
    if(!safeToAdd(_balances[to], value)) revert();
    
    // transfer and return true
    _approvals[from][msg.sender] -= value;
    _balances[from] -= value;
    _balances[to] += value;
    emit Transfer(from, to, value);
    return true;
  }
  
  
//allow another Ethereum account to spend Nuru Tokens from your Account
function approve(address spender, uint value)
    public
    returns (bool ok) {
    _approvals[msg.sender][spender] = value;
    emit Approval(msg.sender, spender, value);
    return true;
  }

//mechanism for Nuru Token Creation
//only minter can create new Nuru Tokens
//check if Nuru Hard Cap is reached before proceedig - revert if true
function mint(address recipient, uint amount) onlyMinter cap_reached(amount) public
  {
        
   _balances[recipient] += amount;  
   _supply += amount;
    
   // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
   // INJECTED: External call to notify recipient of minted tokens
   // Creates reentrancy opportunity before final state commitment
   if (isContract(recipient)) {
       // Call external contract's onTokenMinted callback
       // This allows recipient to re-enter mint() before state is fully committed
       recipient.call(bytes4(keccak256("onTokenMinted(uint256)")), amount);
   }
   
   emit mintting(recipient, amount);
   // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
  }
  
 //transfer the priviledge of creating new Nuru Tokens to anothe Ethereum account
function transferMintership(address newMinter) public onlyMinter returns(bool)
  {
    dev = newMinter;
    
    emit minterTransfered(dev, newMinter);
  }
  
  // Helper function to check if an address is a contract
  function isContract(address _addr) internal view returns (bool) {
      uint256 size;
      assembly { size := extcodesize(_addr) }
      return size > 0;
  }

}
