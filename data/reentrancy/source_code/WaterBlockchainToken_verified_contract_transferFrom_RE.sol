/*
 * ===== SmartInject Injection Details =====
 * Function      : transferFrom
 * Vulnerability : Reentrancy
 * Status        : Verified
 * Type          : Function Modification
 *
 * === Verification Results ===
 * Detected      : True
 * Relevant      : 1 findings
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-no-eth (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Moved allowance update after external call**: The critical `allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);` statement was moved to after the external call, creating a reentrancy window.
 * 
 * 2. **Added recipient notification mechanism**: Introduced an external call `_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)` that attempts to notify the recipient contract about the token transfer.
 * 
 * 3. **Violated Checks-Effects-Interactions pattern**: The function now performs state updates (balances) before the external call, but delays the allowance update until after the external call, creating a vulnerability window.
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup):**
 * - Attacker approves a malicious contract to spend 1000 tokens
 * - `allowed[victim][attacker_contract] = 1000`
 * - This establishes the initial state needed for exploitation
 * 
 * **Transaction 2 (Initial Transfer):**
 * - Attacker calls `transferFrom(victim, malicious_contract, 100)`
 * - Function updates `balances[victim] -= 100` and `balances[malicious_contract] += 100`
 * - External call triggers `malicious_contract.onTokenReceived()`
 * - **Critical**: At this point, `allowed[victim][attacker_contract]` is still 1000 (not yet decremented)
 * 
 * **Transaction 2 (Reentrancy):**
 * - Inside `onTokenReceived()`, the malicious contract calls `transferFrom(victim, malicious_contract, 100)` again
 * - Since allowance hasn't been updated yet, the require check passes
 * - Another 100 tokens are transferred
 * - This can be repeated multiple times within the same transaction
 * 
 * **Transaction 2 (Completion):**
 * - After all reentrant calls, the allowance is finally decremented by only 100
 * - Attacker has successfully transferred more tokens than allowed
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The attack requires initial allowance setup in Transaction 1, which persists in contract storage and enables the vulnerability in Transaction 2.
 * 
 * 2. **Persistent State Dependency**: The vulnerability exploits the gap between balance updates and allowance updates. This requires the allowance state to persist from the initial approval transaction.
 * 
 * 3. **Cannot be Single Transaction**: The attack cannot work in a single transaction because:
 *    - Initial allowance approval must be established first
 *    - The reentrancy vulnerability only exists within the specific execution context of `transferFrom`
 *    - The victim must have tokens and must have approved the attacker's contract beforehand
 * 
 * 4. **Stateful Exploitation**: Each reentrant call within Transaction 2 relies on the persistent state (unchanged allowance) from the initial setup, making this a true stateful, multi-transaction vulnerability.
 * 
 * The vulnerability is realistic because recipient notification is a common pattern in modern token standards, and the allowance update placement creates a subtle but exploitable reentrancy condition.
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
    return c;
  }

  function sub(uint256 a, uint256 b) internal constant returns (uint256) {
    assert(b <= a);
    return a - b;
  }

  function add(uint256 a, uint256 b) internal constant returns (uint256) {
    uint256 c = a + b;
    assert(c >= a);
    return c;
  }
}

    // ERC20 Token Smart Contract
    contract WaterBlockchainToken {
        
        string public constant name = "WaterBlockchainToken";
        string public constant symbol = "WBT";
        uint8 public constant decimals = 4;
        uint public _totalSupply = 1000000000000;
        uint256 public RATE = 1;
        bool public isMinting = false;
        string public constant generatedBy  = "Togen.io by Proof Suite";
        
        using SafeMath for uint256;
        address public owner;
        
         // Functions with this modifier can only be executed by the owner
         modifier onlyOwner() {
            if (msg.sender != owner) {
                throw;
            }
             _;
         }
     
        // Balances for each account
        mapping(address => uint256) balances;
        // Owner of account approves the transfer of an amount to another account
        mapping(address => mapping(address=>uint256)) allowed;

        // Its a payable function works as a token factory.
        function () payable{
            createTokens();
        }

        // Constructor
        constructor() public {
            owner = 0xccb61df4839b42ab0f3bfe6bf860d596248a1bf4; 
            balances[owner] = _totalSupply;
        }

        //allows owner to burn tokens that are not sold in a crowdsale
        function burnTokens(uint256 _value) onlyOwner {

             require(balances[msg.sender] >= _value && _value > 0 );
             _totalSupply = _totalSupply.sub(_value);
             balances[msg.sender] = balances[msg.sender].sub(_value);
             
        }



        // This function creates Tokens  
         function createTokens() payable {
            if(isMinting == true){
                require(msg.value > 0);
                uint256  tokens = msg.value.div(100000000000000).mul(RATE);
                balances[msg.sender] = balances[msg.sender].add(tokens);
                _totalSupply = _totalSupply.add(tokens);
                owner.transfer(msg.value);
            }
            else{
                throw;
            }
        }


        function endCrowdsale() onlyOwner {
            isMinting = false;
        }

        function changeCrowdsaleRate(uint256 _value) onlyOwner {
            RATE = _value;
        }


        
        function totalSupply() constant returns(uint256){
            return _totalSupply;
        }
        // What is the balance of a particular account?
        function balanceOf(address _owner) constant returns(uint256){
            return balances[_owner];
        }

         // Transfer the balance from owner's account to another account   
        function transfer(address _to, uint256 _value)  returns(bool) {
            require(balances[msg.sender] >= _value && _value > 0 );
            balances[msg.sender] = balances[msg.sender].sub(_value);
            balances[_to] = balances[_to].add(_value);
            Transfer(msg.sender, _to, _value);
            return true;
        }
        
    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value)  returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        balances[_to] = balances[_to].add(_value);
        Transfer(_from, _to, _value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient of token transfer (vulnerable external call)
        if (_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
            // Callback succeeded, update allowance after external call
            allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        } else {
            // Callback failed, still update allowance for backward compatibility
            allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        return true;
    }
    
    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) returns(bool){
        allowed[msg.sender][_spender] = _value; 
        Approval(msg.sender, _spender, _value);
        return true;
    }
    
    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) constant returns(uint256){
        return allowed[_owner][_spender];
    }
    
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}