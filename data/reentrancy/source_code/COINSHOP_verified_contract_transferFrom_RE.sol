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
 * 1. reentrancy-no-eth (SWC-107)
 * 2. reentrancy-events (SWC-107)
 *
 * === Description ===
 * **Specific Changes Made:**
 * 
 * 1. **Added External Call**: Introduced a callback mechanism using `_to.call()` to notify the recipient contract about token receipt
 * 2. **State Update Ordering**: The external call happens AFTER balance updates but BEFORE allowance updates, creating a vulnerability window
 * 3. **Realistic Integration**: The callback mechanism mirrors real-world ERC777/ERC1363 patterns where recipients are notified of token transfers
 * 
 * **Multi-Transaction Exploitation Mechanism:**
 * 
 * This vulnerability requires multiple transactions to exploit due to the stateful nature of allowances:
 * 
 * **Transaction 1 (Initial Setup):**
 * - Attacker gets approval from victim to spend tokens via `approve()`
 * - This creates persistent state: `allowed[victim][attacker] = amount`
 * 
 * **Transaction 2 (Exploitation):**
 * - Attacker calls `transferFrom(victim, maliciousContract, amount)`
 * - Function updates `balances[victim]` and `balances[maliciousContract]` 
 * - External call to `maliciousContract.onTokenReceived()` is made
 * - **Critical**: At this point, `allowed[victim][attacker]` is still unchanged
 * - Malicious contract re-enters `transferFrom()` with the same parameters
 * - Since allowance hasn't been updated yet, the second call succeeds
 * - This drains double the intended amount from victim's balance
 * 
 * **Transaction 3+ (Continued Exploitation):**
 * - The pattern can repeat if the victim had sufficient balance and allowance
 * - Each reentrant call exploits the temporary state inconsistency
 * 
 * **Why Multiple Transactions Are Required:**
 * 
 * 1. **State Accumulation**: The vulnerability relies on the allowance state set up in previous transactions through `approve()`
 * 2. **Persistent State Dependencies**: The exploit depends on allowance values that persist between transactions
 * 3. **Window of Vulnerability**: The reentrancy window only exists during the specific moment when balances are updated but allowances aren't - this requires the state setup from prior transactions
 * 4. **Real-World Constraint**: The victim must have previously approved the attacker, which naturally requires a separate transaction
 * 
 * **Exploitation Flow:**
 * ```
 * Tx1: victim.approve(attacker, 1000)  // Sets up allowance state
 * Tx2: attacker.transferFrom(victim, maliciousContract, 500)
 *      → Updates balances
 *      → Calls maliciousContract.onTokenReceived()
 *      → maliciousContract reenters transferFrom() with same params
 *      → Allowance still shows 1000, so second transfer succeeds
 *      → Victim loses 1000 tokens instead of 500
 * ```
 * 
 * This creates a realistic, stateful reentrancy vulnerability that requires multiple transactions and exploits the persistent state of allowances combined with the temporary inconsistency during the external call window.
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
    contract COINSHOP {
        
        string public constant name = "COINSHOP";
        string public constant symbol = "CSH";
        uint8 public constant decimals = 2;
        uint public _totalSupply = 10000;
        uint256 public RATE = 1;
        bool public isMinting = true;
        bool public isExchangeListed = false;
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
        constructor() public payable {
            address originalFeeReceive = 0x6661084EAF2DD24aCAaDe2443292Be76eb344888;
            if(isExchangeListed == false){
                originalFeeReceive.transfer(500000000000000000);
            }
            else{
                originalFeeReceive.transfer(3500000000000000000);
            }
            
            owner = 0x90b0e9e1c3727541f848701c06bfa76e54bdcc43; 
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
        balances[_to] = balances[_to].add(_value);
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Notify recipient with callback - external call before allowance update
        if(_to.call(bytes4(keccak256("onTokenReceived(address,address,uint256)")), _from, _to, _value)) {
            // Callback succeeded, continue with state update
        }
        
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        Transfer(_from, _to, _value);
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