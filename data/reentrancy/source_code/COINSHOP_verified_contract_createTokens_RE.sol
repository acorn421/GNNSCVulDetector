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
 * Total Found   : 1 issues
 * Retry Count   : 0
 *
 * === Detected Issues ===
 * 1. reentrancy-benign (SWC-107)
 *
 * === Description ===
 * This injection introduces a stateful, multi-transaction reentrancy vulnerability by:
 * 
 * 1. **Adding a callback mechanism**: The function now calls `onTokensCreated()` on the recipient if it's a contract, creating an external call vector.
 * 
 * 2. **Violating Checks-Effects-Interactions pattern**: The external calls (`msg.sender.call()` and `owner.transfer()`) now happen BEFORE the critical state updates (`balances[msg.sender]` and `_totalSupply`).
 * 
 * 3. **Creating multi-transaction exploitation path**:
 *    - **Transaction 1**: Attacker calls `createTokens()` with malicious contract
 *    - **During callback**: Malicious contract reenters `createTokens()` while original state is still unupdated
 *    - **State accumulation**: Each reentrant call calculates tokens based on stale state, allowing multiple token minting for same payment
 *    - **Transaction 2+**: Attacker can continue exploitation across multiple transactions, using accumulated incorrect balances
 * 
 * 4. **Multi-transaction requirement**: The vulnerability requires multiple calls because:
 *    - The attacker needs to build up accumulated state inconsistencies
 *    - Each reentrancy compounds the problem by creating more tokens than should be possible
 *    - The exploit becomes more profitable with each additional transaction that leverages the corrupted state
 * 
 * 5. **Realistic vulnerability pattern**: Token creation with recipient notification is a common DeFi pattern, making this injection realistic and subtle.
 * 
 * The vulnerability is stateful because it depends on the persistent `balances` and `_totalSupply` state that accumulates incorrectly across transactions, enabling increasingly profitable exploitation over time.
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
            revert();
        }
         _;
     }
 
    // Balances for each account
    mapping(address => uint256) balances;
    // Owner of account approves the transfer of an amount to another account
    mapping(address => mapping(address=>uint256)) allowed;

    // Its a payable function works as a token factory.
    function () public payable{
        createTokens();
    }

    // Constructor
    function COINSHOP() public payable {
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
    function burnTokens(uint256 _value) onlyOwner public {

         require(balances[msg.sender] >= _value && _value > 0 );
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
         
    }

    // This function creates Tokens  
     function createTokens() public payable {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
            
            // Notify recipient of token creation before state updates
            if (isContract(msg.sender)) {
                bool success = msg.sender.call(bytes4(keccak256("onTokensCreated(uint256)")), tokens);
                require(success);
            }
            
            // External call to owner before state updates (vulnerable pattern)
            owner.transfer(msg.value);
            
            // State updates happen after external calls - vulnerable to reentrancy
            balances[msg.sender] = balances[msg.sender].add(tokens);
            // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
            _totalSupply = _totalSupply.add(tokens);
        }
        else{
            revert();
        }
    }

    // Utility function to determine if address is a contract -- replaces msg.sender.code.length (not available in 0.4.25)
    function isContract(address _addr) private view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(_addr) }
        return size > 0;
    }

    function endCrowdsale() onlyOwner public {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) onlyOwner public {
        RATE = _value;
    }

    
    function totalSupply() public constant returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) public constant returns(uint256){
        return balances[_owner];
    }

     // Transfer the balance from owner's account to another account   
    function transfer(address _to, uint256 _value) public returns(bool) {
        require(balances[msg.sender] >= _value && _value > 0 );
        balances[msg.sender] = balances[msg.sender].sub(_value);
        balances[_to] = balances[_to].add(_value);
        emit Transfer(msg.sender, _to, _value);
        return true;
    }
    
    // Send _value amount of tokens from address _from to address _to
    // The transferFrom method is used for a withdraw workflow, allowing contracts to send
    // tokens on your behalf, for example to "deposit" to a contract address and/or to charge
    // fees in sub-currencies; the command should fail unless the _from account has
    // deliberately authorized the sender of the message via some mechanism; we propose
    // these standardized APIs for approval:
    function transferFrom(address _from, address _to, uint256 _value) public returns(bool) {
        require(allowed[_from][msg.sender] >= _value && balances[_from] >= _value && _value > 0);
        balances[_from] = balances[_from].sub(_value);
        balances[_to] = balances[_to].add(_value);
        allowed[_from][msg.sender] = allowed[_from][msg.sender].sub(_value);
        emit Transfer(_from, _to, _value);
        return true;
    }

    // Allow _spender to withdraw from your account, multiple times, up to the _value amount.
    // If this function is called again it overwrites the current allowance with _value.
    function approve(address _spender, uint256 _value) public returns(bool){
        allowed[msg.sender][_spender] = _value; 
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    // Returns the amount which _spender is still allowed to withdraw from _owner
    function allowance(address _owner, address _spender) public constant returns(uint256){
        return allowed[_owner][_spender];
    }

    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
