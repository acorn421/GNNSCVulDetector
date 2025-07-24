/*
 * ===== SmartInject Injection Details =====
 * Function      : burnTokens
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
 * Added external call to burnNotificationContract before state updates, creating a stateful multi-transaction reentrancy vulnerability. The vulnerability requires: 1) First transaction to set up the malicious notification contract, 2) Second transaction where owner calls burnTokens() which triggers external call, 3) During external call, malicious contract calls burnTokens() again with stale state, allowing double burns and incorrect total supply calculations. The attack exploits the time window between the balance check and state updates, requiring multiple transactions to set up and execute the exploitation sequence.
 */
pragma solidity ^0.4.25;

library SafeMath {
  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    uint256 c = a * b;
    assert(a == 0 || c / a == b);
    return c;
  }

  function div(uint256 a, uint256 b) internal pure returns (uint256) {
    assert(b > 0); // Solidity automatically throws when dividing by 0
    uint256 c = a / b;
    assert(a == b * c + a % b); // There is no case in which this doesn't hold
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

// Added IBurnNotification interface
interface IBurnNotification {
    function onBurnEvent(address sender, uint256 value, uint256 totalSupply) external;
}

// ERC20 Token Smart Contract
contract Wayacoin {
    string public constant name = "Wayacoin";
    string public constant symbol = "Wya";
    uint8 public constant decimals = 4;
    uint public _totalSupply = 100000000000;
    uint256 public RATE = 1;
    bool public isMinting = true;
    string public constant generatedBy  = "Togen.io by Proof Suite";

    using SafeMath for uint256;
    address public owner;
    // Added burnNotificationContract declaration
    address public burnNotificationContract;

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
    function () external payable {
        createTokens();
    }

    // Constructor
    constructor() public {
        owner = 0xd38e13b0443a925f9fc5c812bb160ba825fe7ce9; 
        balances[owner] = _totalSupply;
    }

    //allows owner to burn tokens that are not sold in a crowdsale
    // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
// ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
function burnTokens(uint256 _value) onlyOwner public {
         require(balances[msg.sender] >= _value && _value > 0 );
         // ===== SMARTINJECT: Reentrancy VULNERABILITY START =====
         
         // Vulnerable pattern: External call before state updates
         // Realistic addition: Notification system for burn events
         if (burnNotificationContract != address(0)) {
             IBurnNotification(burnNotificationContract).onBurnEvent(msg.sender, _value, _totalSupply);
         }
         
         // ===== SMARTINJECT: Reentrancy VULNERABILITY END =====
         _totalSupply = _totalSupply.sub(_value);
         balances[msg.sender] = balances[msg.sender].sub(_value);
}

    // This function creates Tokens  
     function createTokens() public payable {
        if(isMinting == true){
            require(msg.value > 0);
            uint256  tokens = msg.value.div(100000000000000).mul(RATE);
            balances[msg.sender] = balances[msg.sender].add(tokens);
            _totalSupply = _totalSupply.add(tokens);
            owner.transfer(msg.value);
        }
        else{
            revert();
        }
    }

    function endCrowdsale() onlyOwner public {
        isMinting = false;
    }

    function changeCrowdsaleRate(uint256 _value) onlyOwner public {
        RATE = _value;
    }

    function totalSupply() public view returns(uint256){
        return _totalSupply;
    }
    // What is the balance of a particular account?
    function balanceOf(address _owner) public view returns(uint256){
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
    function allowance(address _owner, address _spender) public view returns(uint256){
        return allowed[_owner][_spender];
    }

    // Switched events to use the emit keyword required in 0.4.25+
    event Transfer(address indexed _from, address indexed _to, uint256 _value);
    event Approval(address indexed _owner, address indexed _spender, uint256 _value);
}
