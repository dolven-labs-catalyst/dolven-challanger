%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    get_caller_address,
    get_contract_address,
    get_block_number,
    get_block_timestamp,
)
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.bool import TRUE, FALSE
from starkware.cairo.common.math_cmp import is_le
from starkware.cairo.common.math import unsigned_div_rem
from openzeppelin.access.ownable import Ownable
from openzeppelin.security.pausable import Pausable
from starkware.cairo.common.uint256 import (
    Uint256,
    uint256_add,
    uint256_sub,
    uint256_le,
    uint256_lt,
    uint256_check,
    uint256_eq,
    uint256_mul,
    uint256_unsigned_div_rem,
)
from openzeppelin.security.reentrancy_guard import ReentrancyGuard

struct UserDetails:
    member user_address : felt
    member user_finish_timestamp : felt
    member user_submission_count : felt
    member user_unlocked : felt
    member user_country : felt
end

struct SubmissionStruct:
    member user_address : felt
    member question_id : felt
    member submission_time : felt
    member contractAddress : felt
end

@storage_var
func user_submission_bool(user_address : felt, question_id : felt) -> (isSubmitted : felt):
end

@storage_var
func user_submissions(user_address : felt, submission_nonce : felt) -> (
    submission_details : SubmissionStruct
):
end

@storage_var
func user_details_map(user_address : felt) -> (user_info : UserDetails):
end

@storage_var
func users_map(nonce : felt) -> (address : felt):
end

@storage_var
func question_submit_count(question_id : felt) -> (submit_count : felt):
end

@storage_var
func START_TIME() -> (timestamp : felt):
end

@storage_var
func END_TIME() -> (timestamp : felt):
end

@storage_var
func question_count() -> (count : felt):
end

@storage_var
func participant_count() -> (count : felt):
end

@storage_var
func total_submission_count() -> (count : felt):
end

@constructor
func constructor{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _start_time : felt, _end_time : felt
):
    let (msg_sender) = get_caller_address()
    START_TIME.write(_start_time)
    END_TIME.write(_end_time)
    Ownable.initializer(msg_sender)
    ret
end

# # Viewers
@view
func _isPaused{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (res : felt):
    let (status) = Pausable.is_paused()
    return (status)
end

@view
func returnTotalSubmissionCount{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    ) -> (res : felt):
    let (count) = total_submission_count.read()
    return (count)
end

@view
func returnTotalParticipantCount{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    ) -> (res : felt):
    let (count) = participant_count.read()
    return (count)
end

@view
func returnQuestionCount{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    res : felt
):
    let (count) = question_count.read()
    return (count)
end

@view
func returnStartTime{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    res : felt
):
    let (time) = START_TIME.read()
    return (time)
end

@view
func return_isPaused{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    res : felt
):
    let (status) = Pausable.is_paused()
    return (status)
end

@view
func returnEndTime{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    res : felt
):
    let (time) = END_TIME.read()
    return (time)
end

@view
func returnUserDetails{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    user_address_param : felt
) -> (
    _user_address : felt,
    _user_finish_tmp : felt,
    _user_submission_count : felt,
    _user_unlocked : felt,
    _user_country : felt,
    user_questions_len : felt,
    user_questions : felt*,
):
    alloc_locals
    let user_info_struct : UserDetails = user_details_map.read(user_address_param)

    let (questions_len, questions) = recursive_user_questions(
        user_address_param, user_info_struct.user_submission_count, 0
    )

    return (
        user_info_struct.user_address,
        user_info_struct.user_finish_timestamp,
        user_info_struct.user_submission_count,
        user_info_struct.user_unlocked,
        user_info_struct.user_country,
        questions_len,
        questions - questions_len,
    )
end

@view
func returnUserAddresses{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}() -> (
    _user_address_len : felt, _user_address : felt*
):
    alloc_locals

    let (user_address_len, user_address) = recursive_user_addresses(0)

    return (user_address_len, user_address - user_address_len)
end

# # Externals

@external
func submitAnswer{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    question_id : felt, contractAddress : felt
):
    alloc_locals
    ReentrancyGuard._start()
    Pausable.assert_not_paused()

    # definations
    let (msg_sender) = get_caller_address()
    let (time) = get_block_timestamp()
    let _user_info : UserDetails = user_details_map.read(msg_sender)
    let (_startTime) = START_TIME.read()
    let (_endTime) = END_TIME.read()
    let (is_challange_started) = is_le(_startTime, time)
    let (is_challange_finished) = is_le(_endTime, time)
    let (isSubmittedBefore) = user_submission_bool.read(msg_sender, question_id)

    let (_total_submission_count) = total_submission_count.read()
    let _user_submission_count : felt = _user_info.user_submission_count
    let (submit_count) = question_submit_count.read(question_id)
    let (question_count_) = question_count.read()
    let (is_question_id_valid) = is_le(question_id, question_count_)

    # requirements
    with_attr error_message("DolvenChallange::submitAnswer INVALID_QUESTION_ID"):
        assert is_question_id_valid = TRUE
    end
    with_attr error_message("DolvenChallange::submitAnswer CHALLANGE_NOT_STARTED_YET"):
        assert is_challange_started = TRUE
    end
    with_attr error_message("DolvenChallange::submitAnswer CHALLANGE_HAS_FINISHED"):
        assert is_challange_finished = FALSE
    end
    with_attr error_message("DolvenChallange::submitAnswer USER_IS_NOT_WHITELISTED"):
        assert _user_info.user_unlocked = TRUE
    end
    with_attr error_message("DolvenChallange::submitAnswer QUESTION_ALREADY_SUBMITTED"):
        assert isSubmittedBefore = FALSE
    end

    # do something

    user_submission_bool.write(msg_sender, question_id, TRUE)
    let new_submission : SubmissionStruct = SubmissionStruct(
        user_address=msg_sender, question_id=question_id, submission_time=time, contractAddress=contractAddress
    )

    user_submissions.write(msg_sender, _user_submission_count, new_submission)
    question_submit_count.write(question_id, submit_count + 1)

    let new_user_details : UserDetails = UserDetails(
        user_address=msg_sender,
        user_finish_timestamp=time,
        user_submission_count=_user_submission_count + 1,
        user_unlocked=_user_info.user_unlocked,
        user_country=_user_info.user_country,
    )
    user_details_map.write(msg_sender, new_user_details)
    total_submission_count.write(_total_submission_count + 1)
    ReentrancyGuard._end()
    ret
end

@external
func register{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    country_code : felt
):
    alloc_locals
    Pausable.assert_not_paused()
    ReentrancyGuard._start()
    let (msg_sender) = get_caller_address()
    let _user_info : UserDetails = user_details_map.read(msg_sender)
    let (time) = get_block_timestamp()

    let (_startTime) = START_TIME.read()
    let (is_challange_started) = is_le(_startTime, time)
    let (_part_count) = participant_count.read()
    with_attr error_message("DolvenChallange::register REGISTRATION_ENDED"):
        assert is_challange_started = FALSE
    end
    with_attr error_message("DolvenChallange::register ALREADY_REGISTERED"):
        assert _user_info.user_unlocked = FALSE
    end
    users_map.write(_part_count, msg_sender)
    let new_user_details : UserDetails = UserDetails(
        user_address=msg_sender,
        user_finish_timestamp=0,
        user_submission_count=0,
        user_unlocked=TRUE,
        user_country=country_code,
    )
    user_details_map.write(msg_sender, new_user_details)
    participant_count.write(_part_count + 1)
    ReentrancyGuard._end()
    ret
end

@external
func setStartTime{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    startTime : felt
):
    Ownable.assert_only_owner()
    START_TIME.write(startTime)
    ret
end

@external
func setEndTime{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(endTime : felt):
    Ownable.assert_only_owner()
    END_TIME.write(endTime)
    ret
end

@external
func changePause{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}():
    Ownable.assert_only_owner()
    let current_status : felt = Pausable.is_paused()
    if current_status == 1:
        Pausable._unpause()
    else:
        Pausable._pause()
    end

    return ()
end

# # Internals

func recursive_user_questions{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    _user_address : felt, submission_count : felt, index : felt
) -> (question_details_len : felt, question_details : SubmissionStruct*):
    alloc_locals
    let (user_submissions_info) = user_submissions.read(_user_address, index)
    if index == submission_count:
        let (found_questions : SubmissionStruct*) = alloc()
        return (0, found_questions)
    end
    let (questions_len : felt, questions_memory_loc : SubmissionStruct*) = recursive_user_questions(
        _user_address, submission_count, index + 1
    )
    assert [questions_memory_loc] = user_submissions_info
    return (questions_len + 1, questions_memory_loc + SubmissionStruct.SIZE)
end

func recursive_user_addresses{syscall_ptr : felt*, pedersen_ptr : HashBuiltin*, range_check_ptr}(
    index : felt
) -> (participant_addreess_len : felt, participant_addreess : felt*):
    alloc_locals
    let _participant_count : felt = participant_count.read()
    let _user_address : felt = users_map.read(index)
    if index == _participant_count:
        let (addresses_list : felt*) = alloc()
        return (0, addresses_list)
    end
    let (address_len : felt, address_memory_loc : felt*) = recursive_user_addresses(index + 1)
    assert [address_memory_loc] = _user_address
    return (address_len + 1, address_memory_loc + 1)
end
