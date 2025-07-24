/*
 * ===== SmartInject Injection Details =====
 * Function      : enableTimelockedTransfer
 * Vulnerability : Timestamp Dependence
 * Status        : Not Detected
 * Type          : Fallback Function Addition
 *
 * === Verification Results ===
 * Detected      : False
 * Relevant      : 0 findings
 * Total Found   : 3 issues
 * Retry Count   : 0
 *
 * === Description ===
 * This vulnerability introduces timestamp dependence in a stateful, multi-transaction scenario. The vulnerability requires multiple transactions to exploit: 1) First, an attacker calls enableTimelockedTransfer() to set up the timelock state, 2) Then they can manipulate block timestamps across multiple transactions to bypass the timelock mechanism, 3) Finally, they call attemptEarlyUnlock() or transfer() to exploit the timestamp manipulation. The state (isTransferLocked, transferUnlockTime) persists between transactions, making this a stateful vulnerability that cannot be exploited in a single transaction.
 */
pragma solidity ^0.4.24;

interface tokenRecipient { function receiveApproval(address _from, uint256 _value, address _token, bytes _extraData) external; }

/**
 * @title SafeMath
 * @dev Math operations with safety checks that revert on error
 */
library SafeMath {
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        require(c / a == b);
        return c;
    }
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b > 0);
        uint256 c = a / b;
        return c;
    }
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a);
        uint256 c = a - b;
        return c;
    }
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a);
        return c;
    }
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0);
        return a % b;
    }
}

contract AmToken {
    using SafeMath for uint256;
    string public name;
    string public symbol;
    uint8 public decimals = 8;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => mapping (address => uint256)) public allowance;

    // === FALLBACK INJECTION: Timestamp Dependence ===
    // State variables for timelocked transfers
    mapping(address => uint256) public transferUnlockTime;
    mapping(address => bool) public isTransferLocked;
    uint256 public constant TIMELOCK_DURATION = 1 days;
    // === END DECLARATION ADDED ===

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Burn(address indexed from, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event TransferLocked(address indexed account, uint256 unlockTime);
    event TransferUnlocked(address indexed account);

    /**
     * Constructor function
     *
     * Initializes contract with initial supply tokens to the creator of the contract
     */
    constructor (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);
        balanceOf[msg.sender] = totalSupply;
        name = tokenName;
        symbol = tokenSymbol;
    }

    /**
     * Enable timelock for transfers - locks transfers for 24 hours
     */
    function enableTimelockedTransfer() public {
        require(!isTransferLocked[msg.sender], "Transfer already locked");
        transferUnlockTime[msg.sender] = block.timestamp + TIMELOCK_DURATION;
        isTransferLocked[msg.sender] = true;
        emit TransferLocked(msg.sender, transferUnlockTime[msg.sender]);
    }

    function attemptEarlyUnlock() public {
        require(isTransferLocked[msg.sender], "Transfer not locked");
        require(block.timestamp >= transferUnlockTime[msg.sender], "Timelock not expired");
        if (block.timestamp >= transferUnlockTime[msg.sender]) {
            isTransferLocked[msg.sender] = false;
            transferUnlockTime[msg.sender] = 0;
            emit TransferUnlocked(msg.sender);
        }
    }

    /**
     * Override transfer function to respect timelock (vulnerable)
     */
    function transfer(address _to, uint256 _value) public returns (bool) {
        if (isTransferLocked[msg.sender]) {
            require(block.timestamp >= transferUnlockTime[msg.sender], "Transfers are timelocked");
        }
        _transfer(msg.sender, _to, _value);
        return true;
    }

    /**
     * Check if account can transfer tokens (timestamp dependent)
     */
    function canTransfer(address _account) public view returns (bool) {
        if (!isTransferLocked[_account]) {
            return true;
        }
        return block.timestamp >= transferUnlockTime[_account];
    }

    /**
     * Internal transfer, only can be called by this contract
     */
    function _transfer(address _from, address _to, uint256 _value) internal {
        require(_to != address(0));
        require(balanceOf[_from] >= _value);
        require(balanceOf[_to].add(_value) >= balanceOf[_to]);
        uint256 previousBalances = balanceOf[_from].add(balanceOf[_to]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        balanceOf[_to] = balanceOf[_to].add(_value);
        emit Transfer(_from, _to, _value);
        assert(balanceOf[_from].add(balanceOf[_to]) == previousBalances);
    }

    /**
     * Transfer tokens
     *
     * Send `_value` tokens to `_to` from your account
     *
     * @param _to The address of the recipient
     * @param _value the amount to send
     */
    // This duplicates the signature for transfer for direct calls
    function transfer_standard(address _to, uint256 _value) public returns (bool) {
        _transfer(msg.sender, _to, _value);
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool) {
        require(_value <= allowance[_from][msg.sender]);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool) {
        require(_spender != address(0));
        allowance[msg.sender][_spender] = _value;
        emit Approval(msg.sender, _spender, _value);
        return true;
    }

    function approveAndCall(address _spender, uint256 _value, bytes _extraData)
        public
        returns (bool) {
        tokenRecipient spender = tokenRecipient(_spender);
        if (approve(_spender, _value)) {
            spender.receiveApproval(msg.sender, _value, address(this), _extraData);
            return true;
        }
    }

    function burn(uint256 _value) public returns (bool) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] = balanceOf[msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(msg.sender, _value);
        return true;
    }

    function burnFrom(address _from, uint256 _value) public returns (bool) {
        require(balanceOf[_from] >= _value);
        require(_value <= allowance[_from][msg.sender]);
        balanceOf[_from] = balanceOf[_from].sub(_value);
        allowance[_from][msg.sender] = allowance[_from][msg.sender].sub(_value);
        totalSupply = totalSupply.sub(_value);
        emit Burn(_from, _value);
        return true;
    }
}
