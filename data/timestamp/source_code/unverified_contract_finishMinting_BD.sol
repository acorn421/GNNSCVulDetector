/*
 * ===== SmartInject Injection Details =====
 * Function      : finishMinting
 * Vulnerability : Timestamp Dependence
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
 * Introduced a stateful, multi-transaction timestamp dependence vulnerability by:
 * 
 * 1. **Added State Dependencies**: The function now depends on two new state variables:
 *    - `mintingDeadline`: Set by owner in previous transactions to establish when minting should end
 *    - `mintingFinishAttemptTime`: Stores timestamps from previous finish attempts
 * 
 * 2. **Multi-Transaction Requirement**: The vulnerability requires multiple transactions:
 *    - **Transaction 1**: Owner sets `mintingDeadline` in another function (or calls finishMinting when deadline=0)
 *    - **Transaction 2**: Attacker/miner calls finishMinting with manipulated block.timestamp
 *    - **Transaction 3**: Potential follow-up calls to exploit the timestamp comparison logic
 * 
 * 3. **Timestamp Manipulation Vulnerability**: The function has a vulnerable timestamp comparison:
 *    - `if (mintingFinishAttemptTime > block.timestamp + 30)` - This creates a logical flaw where miners can manipulate block.timestamp to make stored timestamps appear to be "in the future"
 *    - Miners can manipulate block.timestamp backward in the second transaction to trigger this condition
 * 
 * 4. **Exploitation Scenario**:
 *    - **Step 1**: Owner sets mintingDeadline to future time (e.g., 1 week from now)
 *    - **Step 2**: Attacker calls finishMinting, function stores current timestamp in mintingFinishAttemptTime
 *    - **Step 3**: Attacker mines next block with manipulated timestamp (set backward by >30 seconds)
 *    - **Step 4**: Attacker calls finishMinting again, the comparison triggers and minting is finished prematurely
 * 
 * 5. **Multi-Transaction Nature**: The vulnerability cannot be exploited in a single transaction because:
 *    - It requires state persistence between calls (mintingFinishAttemptTime storage)
 *    - Block.timestamp manipulation requires mining multiple blocks
 *    - The logical flaw only triggers on subsequent calls after initial state setup
 * 
 * This creates a realistic vulnerability where miners can manipulate timestamps across multiple transactions to bypass time-based access controls.
 */
pragma solidity ^0.4.25;

library Math {

    function sub(uint256 _a, uint256 _b) internal pure returns (uint256) {
        assert(_b <= _a);
        return _a - _b;
    }

    function add(uint256 _a, uint256 _b) internal pure returns (uint256 c) {
        c = _a + _b;
        assert(c >= _a);
        return c;
    }

}

contract MCCToken {

    using Math for uint256;

    string public name = "Material Connection Coin";  //代币名称
    string public symbol = "MCC"; //代币标识
    uint8  public decimals = 15; //代币位数
    uint256 public totalSupply = 160000000 * 10 ** uint256(decimals); //代币发行总量
 
    mapping (address => uint256) public balanceOf; //代币存储
    address public owner; //合约所有者
    
    bool public burnFinished = false;  //TRUE代币停止销毁
    uint256 public burnedSupply = 0; //已销毁在代币数
    uint256 public burnedLimit = 60000000 * 10 ** uint256(decimals); //销毁代币到6千万,停止销毁
    
    bool public mintingFinished = false; //TRUE代币停止增发

    // Variables required for the injected vulnerable finishMinting()
    uint256 public mintingDeadline = 0;
    uint256 public mintingFinishAttemptTime = 0;

    constructor() public {
        balanceOf[msg.sender] = totalSupply;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    modifier canBurn() {
        require(!burnFinished);
        _;
    }
    
    modifier canMint() {
        require(!mintingFinished);
        _;
    }

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed burner, uint256 value);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event Mint(address indexed to, uint256 amount);
    event MintFinished();

    function _transferOwnership(address _newOwner) internal {
        require(_newOwner != address(0));
        emit OwnershipTransferred(owner, _newOwner);
        owner = _newOwner;
    }
    
    //转移合约所有权到另一个账户
    function transferOwnership(address _newOwner) public onlyOwner {
        _transferOwnership(_newOwner);
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != 0x0); 
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to] + _value >= balanceOf[_to]);

        uint previousBalances = balanceOf[_from] + balanceOf[_to];

        balanceOf[_from] -= _value;
        balanceOf[_to] += _value;
        emit Transfer(_from, _to, _value);

        assert(balanceOf[_from] + balanceOf[_to] == previousBalances);
    }

    //代币转账
    function transfer(address _to, uint256 _value) public {
        _transfer(msg.sender, _to, _value);
    }

    function _burn(address _who, uint256 _value) internal {
        require(_value <= balanceOf[_who]);
        
        uint256 burnAmount = _value;

        //最后一笔销毁数量+已销毁数量>销毁上限，则最后一笔销毁数=销毁上限-已销毁数量
        if (burnAmount.add(burnedSupply) > burnedLimit){
            burnAmount = burnedLimit.sub(burnedSupply);
        }

        balanceOf[_who] = balanceOf[_who].sub(burnAmount);
        totalSupply = totalSupply.sub(burnAmount);
        burnedSupply = burnedSupply.add(burnAmount);
        
        //代币销毁到6千万时，平台将停止回购
        if (burnedSupply >= burnedLimit) {
            burnFinished = true;
        }
        
        emit Burn(_who, burnAmount);
        emit Transfer(_who, address(0), burnAmount);
    }

    //代币销毁,减少发行总量
    function burn(uint256 _value) public onlyOwner canBurn {
        _burn(msg.sender, _value);
    }
    
    //代币增发
    function mint(address _to, uint256 _amount) public onlyOwner canMint returns (bool){
        totalSupply = totalSupply.add(_amount);
        balanceOf[_to] = balanceOf[_to].add(_amount);
        emit Mint(_to, _amount);
        emit Transfer(address(0), _to, _amount);
        return true;
    }
    
    // Vulnerable finishMinting 
    function finishMinting() public onlyOwner canMint returns (bool) {
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY START =====
        // Check if minting deadline has been set and passed
        if (mintingDeadline != 0 && block.timestamp >= mintingDeadline) {
            mintingFinished = true;
            emit MintFinished();
            return true;
        }
        
        // If no deadline set, allow immediate finish but store timestamp for validation
        if (mintingDeadline == 0) {
            mintingFinishAttemptTime = block.timestamp;
            return false; // Require second call after timestamp validation
        }
        
        // If deadline is set but not reached, store attempt time for potential bypass
        if (block.timestamp < mintingDeadline) {
            mintingFinishAttemptTime = block.timestamp;
            // Vulnerable: Allow finish if attempt time appears to be in future due to timestamp manipulation
            if (mintingFinishAttemptTime > block.timestamp + 30) { // 30 second threshold
                mintingFinished = true;
                emit MintFinished();
                return true;
            }
            return false;
        }
        
        return false;
        // ===== SMARTINJECT: Timestamp Dependence VULNERABILITY END =====
    }
    
    // (Removed the duplicate/fixed definition and ensured the code compiles)
}
