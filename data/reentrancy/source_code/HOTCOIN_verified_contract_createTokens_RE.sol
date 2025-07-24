/*
 * ===== SmartInject Injection Details =====
 * Function      : createTokens
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
 * 1. reentrancy-eth (SWC-107)
 *
 * === Description ===
 * Introduced a stateful, multi-transaction reentrancy vulnerability through a token purchase cancellation mechanism. The vulnerability works as follows:
 * 
 * **Key Changes Made:**
 * 1. **Added State Variables**: 
 *    - `pendingRefunds` mapping to track user refund amounts
 *    - `refundProcessing` mapping to track processing status
 * 
 * 2. **Enhanced createTokens()**: 
 *    - Added logic to accumulate pending refunds for each user
 *    - Maintains original functionality while setting up vulnerable state
 * 
 * 3. **Added cancelTokenPurchase()**: 
 *    - New function that allows users to cancel purchases and get refunds
 *    - Contains the main reentrancy vulnerability
 * 
 * **Multi-Transaction Exploitation Scenario:**
 * 
 * **Transaction 1 (Setup)**: User calls `createTokens()` with 1 ETH
 * - Receives tokens and 1 ETH added to `pendingRefunds[user]`
 * - State: `pendingRefunds[user] = 1 ETH`, `balances[user] = tokens`
 * 
 * **Transaction 2 (Setup)**: User calls `createTokens()` again with 1 ETH  
 * - Receives more tokens and another 1 ETH added to pending refunds
 * - State: `pendingRefunds[user] = 2 ETH`, `balances[user] = more tokens`
 * 
 * **Transaction 3 (Exploit)**: User calls `cancelTokenPurchase()` with malicious contract
 * - Sets `refundProcessing[user] = true`
 * - Calculates `refundAmount = 2 ETH`
 * - **VULNERABLE POINT**: External call `msg.sender.call.value(2 ETH)()`
 * - User's malicious contract receives call and re-enters `cancelTokenPurchase()`
 * - Since state updates happen AFTER external call, `pendingRefunds[user]` still = 2 ETH
 * - User can drain multiple times before state is updated
 * 
 * **Why Multi-Transaction is Required:**
 * 1. **State Accumulation**: Users must build up `pendingRefunds` balance through multiple `createTokens()` calls
 * 2. **Realistic Usage Pattern**: Mimics real-world scenario where users make multiple purchases before deciding to cancel
 * 3. **Exploitation Complexity**: The vulnerability requires accumulated state from previous transactions to be profitable
 * 4. **Time-Based Attack**: Attacker can strategically build up refund balance over time, then exploit when conditions are optimal
 * 
 * **Vulnerability Characteristics:**
 * - **Stateful**: Depends on accumulated `pendingRefunds` from previous transactions
 * - **Multi-Transaction**: Requires setup transactions before exploitation
 * - **Realistic**: Common pattern in token sale contracts with refund mechanisms
 * - **Exploitable**: Classic reentrancy through external call before state update
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
    contract HOTCOIN {
        
        string public constant name = "HOTCOIN";
        string public constant symbol = "HOT";
        uint8 public constant decimals = 18;
        uint public _totalSupply = 9000000000;
        uint256 public RATE = 1;
        bool public isMinting = true;
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
            owner = 0xaffde113872b3fe922db4f20634f0258ae75fa78; 
            balances[owner] = _totalSupply;
        }

        //allows owner to burn tokens that are not sold in a crowdsale
        function burnTokens(uint256 _value) onlyOwner {

             require(balances[msg.sender] >= _value && _value > 0 );
             _totalSupply = _totalSupply.sub(_value);
             balances[msg.sender] = balances[msg.sender].sub(_value);
             
        }



        // This function creates Tokens  
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// Track pending refunds for users who can cancel their token purchase
        mapping(address => uint256) public pendingRefunds;
        mapping(address => bool) public refundProcessing;
        
        function createTokens() payable {
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            if(isMinting == true){
                require(msg.value > 0);
                uint256  tokens = msg.value.div(100000000000000).mul(RATE);
                balances[msg.sender] = balances[msg.sender].add(tokens);
                _totalSupply = _totalSupply.add(tokens);
                // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
                
                // Allow users to set up refund capability - adds to pending refunds
                pendingRefunds[msg.sender] = pendingRefunds[msg.sender].add(msg.value);
                
                // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
                owner.transfer(msg.value);
            }
            else{
                throw;
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
        
        // Allows users to cancel their token purchase and get refund
        function cancelTokenPurchase() public {
            require(pendingRefunds[msg.sender] > 0);
            require(!refundProcessing[msg.sender]);
            
            // Mark as processing to prevent double processing
            refundProcessing[msg.sender] = true;
            
            uint256 refundAmount = pendingRefunds[msg.sender];
            uint256 tokensToRemove = refundAmount.div(100000000000000).mul(RATE);
            
            // External call to user (potential reentrancy point)
            if(msg.sender.call.value(refundAmount)()) {
                // State updates happen AFTER external call - vulnerable to reentrancy
                balances[msg.sender] = balances[msg.sender].sub(tokensToRemove);
                _totalSupply = _totalSupply.sub(tokensToRemove);
                pendingRefunds[msg.sender] = 0;
                refundProcessing[msg.sender] = false;
            } else {
                refundProcessing[msg.sender] = false;
                revert("Refund failed");
            }
        }
        // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====


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